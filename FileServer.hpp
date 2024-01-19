/*++

Program name:

  Apostol CRM

Module Name:

  FileServer.hpp

Notices:

  Module: File Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_FILE_SERVER_HPP
#define APOSTOL_FILE_SERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        class CFileServer;
        class CFileServerThread;
        class CFileServerThreadMgr;

        //--------------------------------------------------------------------------------------------------------------

        //-- CCurlFileServer -------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CCurlFileServer: public CCurlApi {
        private:

            mutable CStringList m_Into;

        protected:

            void CurlInfo() const override;

        public:

            CCurlFileServer();
            ~CCurlFileServer() override = default;

            int GetResponseCode() const;

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileHandler ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileHandler: public CQueueHandler {
        private:

            CString m_Session;
            CString m_FileId;

            CJSON m_Payload;

            CLocation m_URI;

            CString m_Path;
            CString m_Name;
            CString m_FileName;

            CFileServerThread *m_pThread;
            CHTTPServerConnection *m_pConnection;

            void SetConnection(CHTTPServerConnection *AConnection);

        public:

            CFileHandler(CQueueCollection *ACollection, const CString &Data, COnQueueHandlerEvent && Handler);

            const CString &Session() const { return m_Session; }
            const CString &FileId() const { return m_FileId; }

            CJSON &Payload() { return m_Payload; }
            const CJSON &Payload() const { return m_Payload; }

            CLocation &URI() { return m_URI; }
            const CLocation &URI() const { return m_URI; }

            CString &Path() { return m_Path; }
            const CString &Path() const { return m_Path; }

            CString &Name() { return m_Name; }
            const CString &Name() const { return m_Name; }

            CString &FileName() { return m_FileName; }
            const CString &FileName() const { return m_FileName; }

            CFileServerThread *Thread() const { return m_pThread; };
            void SetThread(CFileServerThread *AThread) { m_pThread = AThread; };

            CHTTPServerConnection *Connection() const { return m_pConnection; };
            void Connection(CHTTPServerConnection *AConnection) { SetConnection(AConnection); };

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServerThread -----------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServerThread: public CThread, public CGlobalComponent {
        private:

            CFileServer *m_pFileServer;

        protected:

            CFileHandler *m_pHandler;
            CFileServerThreadMgr *m_pThreadMgr;

        public:

            explicit CFileServerThread(CFileServer *AFileServer, CFileHandler *AHandler, CFileServerThreadMgr *AThreadMgr);

            ~CFileServerThread() override;

            void Execute() override;

            void TerminateAndWaitFor();

            CFileHandler *Handler() { return m_pHandler; };
            void Handler(CFileHandler *Value) { m_pHandler = Value; };

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServerThreadMgr --------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServerThreadMgr {
        protected:

            CThreadList m_ActiveThreads;
            CThreadPriority m_ThreadPriority;

        public:

            CFileServerThreadMgr();

            virtual ~CFileServerThreadMgr();

            virtual CFileServerThread *GetThread(CFileServer *AFileServer, CFileHandler *AHandler);

            virtual void ReleaseThread(CFileServerThread *AThread) abstract;

            void TerminateThreads();

            CThreadList &ActiveThreads() { return m_ActiveThreads; }
            const CThreadList &ActiveThreads() const { return m_ActiveThreads; }

            CThreadPriority ThreadPriority() const { return m_ThreadPriority; }
            void ThreadPriority(CThreadPriority Value) { m_ThreadPriority = Value; }

        }; // CFileServerThreadMgr

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServerThreadMgrDefault -------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServerThreadMgrDefault : public CFileServerThreadMgr {
            typedef CFileServerThreadMgr inherited;

        public:

            ~CFileServerThreadMgrDefault() override {
                TerminateThreads();
            };

            CFileServerThread *GetThread(CFileServer *AFileServer, CFileHandler *AHandler) override {
                return inherited::GetThread(AFileServer, AHandler);
            };

            void ReleaseThread(CFileServerThread *AThread) override {
                if (!IsCurrentThread(AThread)) {
                    AThread->FreeOnTerminate(false);
                    AThread->TerminateAndWaitFor();
                    FreeAndNil(AThread);
                } else {
                    AThread->FreeOnTerminate(true);
                    AThread->Terminate();
                }
            };

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServer: public CQueueCollection, public CApostolModule {
        private:

            CString m_Session;

            CString m_Conf;
            CString m_Path;
            CString m_Agent;
            CString m_Host;

            CDateTime m_CheckDate;
            CDateTime m_AuthDate;

            CFileServerThreadMgrDefault m_ThreadMgr;

            static CJSON ParamsToJson(const CStringList &Params);
            static CJSON HeadersToJson(const CHeaders &Headers);

            void InitMethods() override;

            void InitListen();
            void CheckListen();

            void Authentication();
            void SignOut(const CString &Session);

            CFileServerThread *GetThread(CFileHandler *AHandler);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static CString GetSession(const CHTTPRequest &Request);

            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);
            static int CheckError(const CJSON &Json, CString &ErrorMessage);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

            static void DeleteFile(const CString &FileName);
            static void SendFile(CHTTPServerConnection *AConnection, const CString &FileName);

            CPQPollQuery *ExecuteSQL(const CStringList &SQL, CFileHandler *AHandler,
                COnApostolModuleSuccessEvent && OnSuccess, COnApostolModuleFailEvent && OnFail = nullptr);

            CString VerifyToken(const CString &Token);

        protected:

            static void DoError(const Delphi::Exception::Exception &E);
            void DoError(CQueueHandler *AHandler, const CString &Message);

            void DoDone(CFileHandler *AHandler, const CHTTPReply &Reply);
            void DoFail(CFileHandler *AHandler, const CString &Message);

            void DoFile(CQueueHandler *AHandler);
            void DoLink(CQueueHandler *AHandler);
            void DoGetFile(CQueueHandler *AHandler);

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify) override;

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CFileServer(CModuleProcess *AProcess);

            ~CFileServer() override = default;

            static class CFileServer *CreateModule(CModuleProcess *AProcess) {
                return new CFileServer(AProcess);
            }

            void Initialization(CModuleProcess *AProcess) override;

            CPQPollQuery *GetQuery(CPollConnection *AConnection) override;

            void Heartbeat(CDateTime Now) override;

            void UnloadQueue() override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;
            bool CheckAuthorization(CHTTPServerConnection *AConnection, CString &Session, CAuthorization &Authorization);

            void CURL(CFileHandler *AHandler);

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_FILE_SERVER_HPP
