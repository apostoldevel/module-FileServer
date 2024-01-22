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

#include "FileCommon.hpp"

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServer: public CFileCommon {
        private:

            void InitMethods() override;

            static CString GetSession(const CHTTPRequest &Request);
            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);

            CString VerifyToken(const CString &Token);

            static void DoDisconnected(CObject *Sender);

        protected:

            void DoGetFile(CQueueHandler *AHandler);

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

        public:

            explicit CFileServer(CModuleProcess *AProcess);

            ~CFileServer() override = default;

            static class CFileServer *CreateModule(CModuleProcess *AProcess) {
                return new CFileServer(AProcess);
            }

            void Heartbeat(CDateTime Now) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;
            bool CheckAuthorization(CHTTPServerConnection *AConnection, CString &Session, CAuthorization &Authorization);

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_FILE_SERVER_HPP
