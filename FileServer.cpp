/*++

Program name:

  Apostol CRM

Module Name:

  FileServer.cpp

Notices:

  Module: File Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "FileServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#define API_BOT_USERNAME "apibot"

#define QUERY_INDEX_AUTH     0
#define QUERY_INDEX_DATA     1

#define PG_CONFIG_NAME "helper"
#define PG_LISTEN_NAME "file"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        CString squeeze(const CString &data, const char litter = '\n') {
            CString result;
            size_t pos = 0;
            TCHAR ch = data.at(pos++);

            while (ch) {
                if (ch != litter)
                    result.Append(ch);
                ch = data.at(pos++);
            }

            return result;
        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileHandler ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CFileHandler::CFileHandler(CQueueCollection *ACollection, const CString &Data, COnQueueHandlerEvent && Handler):
                CQueueHandler(ACollection, static_cast<COnQueueHandlerEvent &&> (Handler)) {

            m_Payload = Data;

            m_Session = m_Payload["session"].AsString();
            m_FileId = m_Payload["id"].AsString();
        }

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CFileServer::CFileServer(CModuleProcess *AProcess): CQueueCollection(Config()->PostgresPollMin()),
                CApostolModule(AProcess, "file server", "module/FileServer") {

            m_Headers.Add("Authorization");

            m_Agent = CString().Format("File Server (%s)", GApplication->Title().c_str());
            m_Host = CApostolModule::GetIPByHostName(CApostolModule::GetHostName());

            m_Conf = PG_CONFIG_NAME;

            m_CheckDate = 0;
            m_AuthDate = 0;

            CFileServer::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_Methods.AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoGet, this, _1)));
            m_Methods.AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoPost, this, _1)));
            m_Methods.AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoOptions, this, _1)));
            m_Methods.AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_Methods.AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPReply::CStatusType CFileServer::ErrorCodeToStatus(int ErrorCode) {
            CHTTPReply::CStatusType status = CHTTPReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        status = CHTTPReply::unauthorized;
                        break;

                    case 403:
                        status = CHTTPReply::forbidden;
                        break;

                    case 404:
                        status = CHTTPReply::not_found;
                        break;

                    case 500:
                        status = CHTTPReply::internal_server_error;
                        break;

                    default:
                        status = CHTTPReply::bad_request;
                        break;
                }
            }

            return status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CFileServer::CheckError(const CJSON &Json, CString &ErrorMessage) {
            int errorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    errorCode = error[_T("code")].AsInteger();
                } else {
                    errorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (errorCode >= 10000)
                    errorCode = errorCode / 100;

                if (errorCode < 0)
                    errorCode = 400;
            }

            return errorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CFileServer::VerifyToken(const CString &Token) {
            auto decoded = jwt::decode(Token);

            const auto &aud = CString(decoded.get_audience());
            const auto &alg = CString(decoded.get_algorithm());
            const auto &iss = CString(decoded.get_issuer());

            const auto &Providers = Server().Providers();

            CString Application;
            const auto index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto &Provider = Providers[index].Value();
            const auto &Secret = OAuth2::Helper::GetSecret(Provider, Application);

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::error::token_verification_exception(jwt::error::token_verification_error::issuer_missmatch);

            if (alg == "HS256") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs256{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS384") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs384{Secret});
                verifier.verify(decoded);
            } else if (alg == "HS512") {
                auto verifier = jwt::verify()
                        .allow_algorithm(jwt::algorithm::hs512{Secret});
                verifier.verify(decoded);
            }

            return decoded.get_payload_claim("sub").as_string();
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CFileServer::GetSession(const CHTTPRequest &Request) {
            const auto &headerSession = Request.Headers.Values(_T("Session"));
            const auto &cookieSession = Request.Cookies.Values(_T("SID"));

            return headerSession.IsEmpty() ? cookieSession : headerSession;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization) {

            const auto &caHeaders = Request.Headers;
            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {
                const auto &caSession = GetSession(Request);

                if (caSession.Length() != 40)
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;
                Authorization.Username = caSession;
            } else {
                Authorization << caAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckAuthorization(CHTTPServerConnection *AConnection, CString &Session, CAuthorization &Authorization) {

            const auto &caRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(caRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Session = VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic) {
                    if (Authorization.Type == CAuthorization::atSession) {
                        Session = Authorization.Username;
                        return true;
                    }
                    AConnection->Data().Values("Authorization", "Basic");
                }

                ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
            } catch (jwt::error::token_expired_exception &e) {
                ReplyError(AConnection, CHTTPReply::forbidden, e.what());
            } catch (jwt::error::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DeleteFile(const CString &FileName) {
            if (FileExists(FileName.c_str())) {
                if (::unlink(FileName.c_str()) == FILE_ERROR) {
                    Log()->Error(APP_LOG_ALERT, errno, _T("could not delete file: \"%s\" error: "), FileName.c_str());
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoError(const Delphi::Exception::Exception &E) {
            Log()->Error(APP_LOG_ERR, 0, "[FileServer] Error: %s", E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoFile(CQueueHandler *AHandler) {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;

                auto pHandler = dynamic_cast<CFileHandler *> (APollQuery->Binding());

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &authorize = pqResults[QUERY_INDEX_AUTH].First();

                    if (authorize["authorized"] != "t")
                        throw Delphi::Exception::ExceptionFrm("Authorization failed: %s", authorize["message"].c_str());

                    if (pqResults[QUERY_INDEX_DATA].Count() == 1) {
                        const auto &caFile = pqResults[QUERY_INDEX_DATA].First();

                        const auto &name = caFile["name"];
                        const auto &path = caFile["path"];
                        const auto &data = caFile["data"];

                        if (!data.empty()) {
                            const auto &caFilePath = m_Path + (path_separator(path.front()) ? path : "/" + path);
                            CApplication::MkDir(caFilePath);
                            const auto &caFileName = path_separator(caFilePath.back()) ? caFilePath + name : caFilePath + "/" + name;

                            DeleteFile(caFileName);

                            auto decode = base64_decode(squeeze(data));
                            decode.SaveToFile(caFileName.c_str());
                        }
                    }
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }

                DeleteHandler(pHandler);
                UnloadQueue();
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                auto pHandler = dynamic_cast<CFileHandler *> (APollQuery->Binding());
                DeleteHandler(pHandler);
                UnloadQueue();
                DoError(E);
            };

            auto pHandler = dynamic_cast<CFileHandler *> (AHandler);

            const auto &operation = pHandler->Payload()["operation"].AsString();
            const auto &name = pHandler->Payload()["name"].AsString();
            const auto &path = pHandler->Payload()["path"].AsString();

            if (operation == "DELETE") {
                const auto &caFilePath = m_Path + (path_separator(path.front()) ? path : "/" + path);
                const auto &caFileName = path_separator(caFilePath.back()) ? caFilePath + name : caFilePath + "/" + name;

                DeleteFile(caFileName);

                DeleteHandler(AHandler);
                UnloadQueue();
            } else {
                CStringList SQL;

                api::authorize(SQL, pHandler->Session());
                api::get_file(SQL, pHandler->FileId());

                try {
                    ExecSQL(SQL, AHandler, OnExecuted, OnException);
                    AHandler->Allow(false);
                    IncProgress();
                } catch (Delphi::Exception::Exception &E) {
                    DeleteHandler(AHandler);
                    DoError(E);
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoGetFile(CHTTPServerConnection *AConnection, const CString &Session,
                const CString &Path, const CString &Name) {

            auto OnSuccess = [this](CHTTPServerConnection *AConnection, CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &authorize = pqResults[QUERY_INDEX_AUTH].First();

                    if (authorize["authorized"] != "t")
                        throw Delphi::Exception::ExceptionFrm("Authorization failed: %s", authorize["message"].c_str());

                    auto &Reply = AConnection->Reply();

                    if (pqResults[QUERY_INDEX_DATA].Count() == 0) {
                        AConnection->SendStockReply(CHTTPReply::not_found, true);
                        return;
                    }

                    const auto &caFile = pqResults[QUERY_INDEX_DATA].First();

                    const auto &name = caFile["name"];
                    const auto &path = caFile["path"];
                    const auto &date = caFile["date"];
                    const auto &data = caFile["data"].IsEmpty() ? CString() : caFile["data"];

                    CString sFileExt;
                    TCHAR szBuffer[MAX_BUFFER_SIZE + 1] = {0};

                    sFileExt = ExtractFileExt(szBuffer, name.c_str());

                    if (data.IsEmpty()) {
                        Reply.Content.Clear();
                        AConnection->SendStockReply(CHTTPReply::no_content, true);
                        return;
                    }

                    const auto &caFilePath = m_Path + (path_separator(path.front()) ? path.substr(1) : path);
                    ForceDirectories(caFilePath.c_str(), 0700);
                    const auto &caFileName = path_separator(caFilePath.back()) ? caFilePath + name : caFilePath + "/" + name;

                    DeleteFile(caFileName);

                    Reply.Content = base64_decode(squeeze(data));
                    Reply.Content.SaveToFile(caFileName.c_str());

                    AConnection->SendReply(CHTTPReply::ok, Mapping::ExtToType(sFileExt.c_str()), true);
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(AConnection, CHTTPReply::not_found, E.what());
                } catch (std::exception &e) {
                    ReplyError(AConnection, CHTTPReply::bad_request, e.what());
                }
            };

            auto OnContinue = [](CHTTPServerConnection *AConnection, CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &authorize = pqResults[QUERY_INDEX_AUTH].First();

                    if (authorize["authorized"] != "t")
                        throw Delphi::Exception::ExceptionFrm("Authorization failed: %s", authorize["message"].c_str());

                    auto &Reply = AConnection->Reply();

                    const auto &name = AConnection->Data()["name"];
                    const auto &filename = AConnection->Data()["filename"];

                    CString sFileExt;
                    TCHAR szBuffer[MAX_BUFFER_SIZE + 1] = {0};

                    sFileExt = ExtractFileExt(szBuffer, name.c_str());

                    auto sModified = StrWebTime(FileAge(filename.c_str()), szBuffer, sizeof(szBuffer));
                    if (sModified != nullptr) {
                        Reply.AddHeader(_T("Last-Modified"), sModified);
                    }

                    Reply.Content.LoadFromFile(filename);

                    AConnection->SendReply(CHTTPReply::ok, Mapping::ExtToType(sFileExt.c_str()), true);
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(AConnection, CHTTPReply::not_found, E.what());
                } catch (std::exception &e) {
                    ReplyError(AConnection, CHTTPReply::bad_request, e.what());
                }
            };

            auto OnFail = [](CHTTPServerConnection *AConnection, const Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::internal_server_error, E.what());
            };

            CString sName(CHTTPServer::URLDecode(Name));

            if (path_separator(sName.back())) {
                sName += APOSTOL_INDEX_FILE;
            }

            const auto &caFilePath = m_Path + (path_separator(Path.front()) ? Path.SubString(1) : Path);
            const auto &caFileName = path_separator(caFilePath.back()) ? caFilePath + sName : caFilePath + "/" + sName;

            AConnection->Data().AddPair("name", sName);
            AConnection->Data().AddPair("filepath", caFilePath);
            AConnection->Data().AddPair("filename", caFileName);

            CStringList SQL;

            if (FileExists(caFileName.c_str())) {
                api::authorize(SQL, Session);

                try {
                    ExecuteSQL(SQL, AConnection, OnContinue, OnFail);
                } catch (Delphi::Exception::Exception &E) {
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            } else {
                api::authorize(SQL, Session);
                api::get_file(SQL, Name, Path);

                try {
                    ExecuteSQL(SQL, AConnection, OnSuccess, OnFail);
                } catch (Delphi::Exception::Exception &E) {
                    Log()->Error(APP_LOG_EMERG, 0, E.what());
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());
            if (pConnection != nullptr && pConnection->Connected()) {
                ReplyError(pConnection, CHTTPReply::internal_server_error, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify) {
            DebugNotify(AConnection, ANotify);

            if (CompareString(ANotify->relname, PG_LISTEN_NAME) == 0) {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                new CFileHandler(this, ANotify->extra, [this](auto &&Handler) { DoFile(Handler); });
#else
                new CFileHandler(this, ANotify->extra, std::bind(&CFileServer::DoFile, this, _1));
#endif
                UnloadQueue();
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {
            CPQResult *pResult;

            try {
                for (int i = 0; i < APollQuery->Count(); i++) {
                    pResult = APollQuery->Results(i);
                    if (pResult->ExecStatus() != PGRES_TUPLES_OK)
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                }
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            DoError(E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoGet(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();

            CString sPath(caRequest.Location.pathname);

            // Request path must be absolute and not contain "..".
            if (sPath.empty() || sPath.front() != '/' || sPath.find(_T("..")) != CString::npos) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            CStringList slRouts;
            CString sName;

            if (path_separator(sPath.back())) {
                sPath += APOSTOL_INDEX_FILE;
            }

            SplitColumns(sPath, slRouts, '/');

            sPath = "/";
            for (int i = 1; i < slRouts.Count() - 1; ++i) {
                sPath << slRouts[i];
                sPath << "/";
            }
            sName << slRouts.Last();

            CString Session;

            if (sPath == "/public/") {
                Session = m_Session;
            } else {
                CAuthorization Authorization;
                if (!CheckAuthorization(AConnection, Session, Authorization)) {
                    return;
                }
            }

            DoGetFile(AConnection, Session, sPath, sName);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPost(CHTTPServerConnection *AConnection) {

            const auto &caRequest = AConnection->Request();

            CString sPath(caRequest.Location.pathname);

            // Request path must be absolute and not contain "..".
            if (sPath.empty() || sPath.front() != '/' || sPath.find(_T("..")) != CString::npos) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            MethodNotAllowed(AConnection);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Authentication() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {

                CPQueryResults pqResults;
                CStringList SQL;

                try {
                    CApostolModule::QueryToResults(APollQuery, pqResults);

                    const auto &session = pqResults[0].First()["session"];

                    m_Session = pqResults[1].First()["get_session"];

                    m_AuthDate = Now() + (CDateTime) 24 / HoursPerDay;

                    SignOut(session);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            const auto &caProviders = Server().Providers();
            const auto &caProvider = caProviders.DefaultValue();

            const auto &clientId = caProvider.ClientId(SERVICE_APPLICATION_NAME);
            const auto &clientSecret = caProvider.Secret(SERVICE_APPLICATION_NAME);

            CStringList SQL;

            api::login(SQL, clientId, clientSecret, m_Agent, m_Host);
            api::get_session(SQL, API_BOT_USERNAME, m_Agent, m_Host);

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::SignOut(const CString &Session) {
            CStringList SQL;

            api::signout(SQL, Session);

            try {
                ExecSQL(SQL);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::InitListen() {

            auto OnExecuted = [this](CPQPollQuery *APollQuery) {
                try {
                    auto pResult = APollQuery->Results(0);

                    if (pResult->ExecStatus() != PGRES_COMMAND_OK) {
                        throw Delphi::Exception::EDBError(pResult->GetErrorMessage());
                    }

                    APollQuery->Connection()->Listeners().Add(PG_LISTEN_NAME);
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                    APollQuery->Connection()->OnNotify([this](auto && APollQuery, auto && ANotify) { DoPostgresNotify(APollQuery, ANotify); });
#else
                    APollQuery->Connection()->OnNotify(std::bind(&CFileServer::DoPostgresNotify, this, _1, _2));
#endif
                } catch (Delphi::Exception::Exception &E) {
                    DoError(E);
                }
            };

            auto OnException = [this](CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
                DoError(E);
            };

            CStringList SQL;

            SQL.Add("LISTEN " PG_LISTEN_NAME ";");

            try {
                ExecSQL(SQL, nullptr, OnExecuted, OnException);
            } catch (Delphi::Exception::Exception &E) {
                DoError(E);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::CheckListen() {
            if (!PQClient(PG_CONFIG_NAME).CheckListen(PG_LISTEN_NAME))
                InitListen();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::UnloadQueue() {
            const auto index = m_Queue.IndexOf(this);
            if (index != -1) {
                const auto queue = m_Queue[index];
                for (int i = 0; i < queue->Count(); ++i) {
                    auto pHandler = (CFileHandler *) queue->Item(i);
                    if (pHandler != nullptr) {
                        pHandler->Handler();
                        if (m_Progress >= m_MaxQueue)
                            break;
                    }
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        CPQPollQuery *CFileServer::GetQuery(CPollConnection *AConnection) {
            CPQPollQuery *pQuery = m_pModuleProcess->GetQuery(AConnection, m_Conf);

            if (Assigned(pQuery)) {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
                pQuery->OnPollExecuted([this](auto && APollQuery) { DoPostgresQueryExecuted(APollQuery); });
                pQuery->OnException([this](auto && APollQuery, auto && AException) { DoPostgresQueryException(APollQuery, AException); });
#else
                pQuery->OnPollExecuted(std::bind(&CFileServer::DoPostgresQueryExecuted, this, _1));
                pQuery->OnException(std::bind(&CFileServer::DoPostgresQueryException, this, _1, _2));
#endif
            }

            return pQuery;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Initialization(CModuleProcess *AProcess) {
            m_Path = Config()->IniFile().ReadString(SectionName().c_str(), "path", "files/");

            if (!path_separator(m_Path.front())) {
                m_Path = Config()->Prefix() + m_Path;
            }

            if (path_separator(m_Path.back())) {
                m_Path.SetLength(m_Path.Length() - 1);
            }

            CApplication::MkDir(m_Path);
            CApplication::ChMod(m_Path, 0777);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Heartbeat(CDateTime Now) {
            if ((Now >= m_CheckDate)) {
                m_CheckDate = Now + (CDateTime) 1 / MinsPerDay; // 1 min
                CheckListen();
            }

            if ((Now >= m_AuthDate)) {
                m_AuthDate = Now + (CDateTime) 5 / SecsPerDay; // 5 sec
                Authentication();
            }

            UnloadQueue();
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName().c_str(), "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 6) == _T("/file/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}