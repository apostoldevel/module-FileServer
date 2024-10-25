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

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

#define QUERY_INDEX_AUTH     0
#define QUERY_INDEX_DATA     1

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CFileServer::CFileServer(CModuleProcess *AProcess): CFileCommon(AProcess, "file server", "module/FileServer") {
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

        void CFileServer::DoGetFile(CQueueHandler *AHandler) {

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

                    const auto &type = caFile["type"];
                    const auto &path = caFile["path"];
                    const auto &name = caFile["name"];
                    const auto &date = caFile["date"];
                    const auto &data = caFile["data"];

                    if (data.empty()) {
                        Reply.Content.Clear();
                        AConnection->SendStockReply(CHTTPReply::no_content, true);
                        return;
                    }

                    const auto &caPath = m_Path + (path_separator(path.front()) ? path.substr(1) : path);
                    ForceDirectories(caPath.c_str(), 0755);
                    const auto &caAbsoluteName = path_separator(caPath.back()) ? caPath + name : caPath + "/" + name;

                    if (type == "-") {
                        DeleteFile(caAbsoluteName);

                        Reply.Content = base64_decode(squeeze(data));
                        Reply.Content.SaveToFile(caAbsoluteName.c_str());

                        SendFile(AConnection, caAbsoluteName);

                        return;
                    } else if (type == "l" || type == "s") {
                        const auto &decode = base64_decode(squeeze(data));
                        if ((decode.substr(0, 8) == FILE_COMMON_HTTPS || decode.substr(0, 7) == FILE_COMMON_HTTP)) {
                            CString uri(decode);

                            auto pHandler = new CFileHandler(this, CString().Format(R"({"session": "%s"})", m_Session.c_str()), [this](auto &&Handler) {
                                if (m_Type == "curl") {
                                    DoCURL(dynamic_cast<CFileHandler *> (Handler));
                                } else {
                                    DoFetch(dynamic_cast<CFileHandler *> (Handler));
                                }
                            });

                            if (type == 's') {
                                uri += path;
                                uri += name;
                            }

                            pHandler->URI() = uri;

                            pHandler->AbsoluteName() = caAbsoluteName;
                            pHandler->Connection(AConnection);
                            UnloadQueue();

                            return;
                        } else if (decode == caAbsoluteName) {
                            Reply.Content.LoadFromFile(caAbsoluteName.c_str());
                            SendFile(AConnection, caAbsoluteName);

                            return;
                        }
                    }

                    ReplyError(AConnection, CHTTPReply::not_found, "Not found");
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

                    const auto &absolute_name = AConnection->Data()["absolute_name"];

                    SendFile(AConnection, absolute_name);
                } catch (Delphi::Exception::Exception &E) {
                    ReplyError(AConnection, CHTTPReply::not_found, E.what());
                } catch (std::exception &e) {
                    ReplyError(AConnection, CHTTPReply::bad_request, e.what());
                }
            };

            auto OnFail = [](CHTTPServerConnection *AConnection, const Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::internal_server_error, E.what());
            };

            auto pHandler = dynamic_cast<CFileHandler *> (AHandler);

            if (pHandler == nullptr)
                return;

            AHandler->Allow(false);
            IncProgress();

            auto pConnection = pHandler->Connection();

            if (!(pConnection != nullptr && pConnection->Connected())) {
                DeleteHandler(pHandler);
                return;
            }

            const CString Session(pHandler->Session());
            const CString Path(pHandler->Path());
            const CString Name(pHandler->Name());

            CString sName(CHTTPServer::URLDecode(Name));

            if (path_separator(sName.back())) {
                sName += APOSTOL_INDEX_FILE;
            }

            const auto &caPath = m_Path + (path_separator(Path.front()) ? Path.SubString(1) : Path);
            const auto &caAbsoluteName = path_separator(caPath.back()) ? caPath + sName : caPath + "/" + sName;

            pConnection->Data().AddPair("path", caPath);
            pConnection->Data().AddPair("name", sName);
            pConnection->Data().AddPair("absolute_name", caAbsoluteName);

            CStringList SQL;

            if (FileExists(caAbsoluteName.c_str())) {
                if (Session == m_Session) {
                    SendFile(pConnection, caAbsoluteName);
                    DeleteHandler(AHandler);
                } else {
                    api::authorize(SQL, Session);

                    try {
                        ExecuteSQL(SQL, pHandler, OnContinue, OnFail);
                    } catch (Delphi::Exception::Exception &E) {
                        DoError(AHandler, E.Message());
                    }
                }
            } else {
                api::authorize(SQL, Session);
                api::get_file(SQL, Name, Path);

                try {
                    ExecuteSQL(SQL, pHandler, OnSuccess, OnFail);
                } catch (Delphi::Exception::Exception &E) {
                    DoError(AHandler, E.Message());
                }
            }
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

            if (sPath.SubString(0, 8) == "/public/") {
                Session = m_Session;
            } else {
                CAuthorization Authorization;
                if (!CheckAuthorization(AConnection, Session, Authorization)) {
                    return;
                }
            }

#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            auto pHandler = new CFileHandler(this, CString().Format(R"({"session": "%s", "path": "%s", "name": "%s"})", Session.c_str(), sPath.c_str(), sName.c_str()), [this](auto &&Handler) { DoGetFile(Handler); });
            AConnection->OnDisconnected([this](auto &&Sender) { DoDisconnected(Sender); });
#else
            auto pHandler = new CFileHandler(this, CString().Format(R"({"session": "%s", "path": "%s", "name": "%s"})", Session.c_str(), sPath.c_str(), sName.c_str()), std::bind(&CFileServer::DoGetFile, this, _1));
            AConnection->OnDisconnected(std::bind(&CFileServer::DoDisconnected, this, _1));
#endif
            pHandler->Connection(AConnection);

            UnloadQueue();
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

        void CFileServer::DoDisconnected(CObject *Sender) {
            auto pConnection = dynamic_cast<CHTTPServerConnection *>(Sender);
            if (Assigned(pConnection)) {
                auto pHandler = dynamic_cast<CFileHandler *> (pConnection->Binding());
                if (Assigned(pHandler))
                    pHandler->Connection(nullptr);
                auto pSocket = pConnection->Socket();
                if (pSocket != nullptr) {
                    auto pHandle = pSocket->Binding();
                    if (Assigned(pHandle)) {
                        Log()->Notice(_T("[%s] [%s:%d] Client disconnected."), ModuleName().c_str(), pHandle->PeerIP(), pHandle->PeerPort());
                    }
                } else {
                    Log()->Notice(_T("[%s] Client disconnected."), ModuleName().c_str());
                }
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Heartbeat(CDateTime Now) {
            if ((Now >= m_AuthDate)) {
                m_AuthDate = Now + (CDateTime) 5 / SecsPerDay; // 5 sec
                Authentication();
            }

            UnloadQueue();
            CheckTimeOut(Now);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Initialization(CModuleProcess *AProcess) {
            CFileCommon::Initialization(AProcess);
            Config()->IniFile().ReadSectionValues(CString().Format("%s/endpoints", SectionName()).c_str(), &m_EndPoints);
            if (m_EndPoints.Count() == 0)
                m_EndPoints.Add("/file/*");
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName().c_str(), "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckLocation(const CLocation &Location) {
            return AllowedLocation(Location.pathname, m_EndPoints);
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}