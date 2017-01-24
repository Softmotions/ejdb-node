/**************************************************************************************************
 *  EJDB database library http://ejdb.org
 *  Copyright (C) 2012-2013 Softmotions Ltd <info@softmotions.com>
 *
 *  This file is part of EJDB.
 *  EJDB is free software; you can redistribute it and/or modify it under the terms of
 *  the GNU Lesser General Public License as published by the Free Software Foundation; either
 *  version 2.1 of the License or any later version.  EJDB is distributed in the hope
 *  that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *  You should have received a copy of the GNU Lesser General Public License along with EJDB;
 *  if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 *  Boston, MA 02111-1307 USA.
 *************************************************************************************************/

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef EJDB_CMD_H
#define	EJDB_CMD_H

#include <uv.h>
#include <v8.h>
#include <string>

#include <nan.h>

namespace ejdb {

    template < typename T, typename D = void > class EIOCmdTask {
    public:

        //uv request
        uv_work_t uv_work;

        Nan::Callback *cb;
        T* wrapped;

        //cmd spec
        int cmd;
        D* cmd_data;

        //cmd return data
        int cmd_ret;
        int cmd_ret_data_length;
        std::string cmd_ret_msg;

        //entity type
        int entity;

        //Pointer to free_cmd_data function
        void (*free_cmd_data)(EIOCmdTask<T, D>*);


    public:

        static void free_val(EIOCmdTask<T, D>* dtask) {
            if (dtask->cmd_data) {
                free(dtask->cmd_data);
                dtask->cmd_data = NULL;
            }
        }

        static void delete_val(EIOCmdTask<T, D>* dtask) {
            if (dtask->cmd_data) {
                delete dtask->cmd_data;
                dtask->cmd_data = NULL;
            }
        }

    public:

        EIOCmdTask(const v8::Handle<v8::Function>& _cb, T* _wrapped, int _cmd,
                D* _cmd_data, void (*_free_cmd_data)(EIOCmdTask<T, D>*)) :
        wrapped(_wrapped), cmd(_cmd), cmd_data(_cmd_data), cmd_ret(0), cmd_ret_data_length(0), entity(0) {

            this->free_cmd_data = _free_cmd_data;
            this->cb = new Nan::Callback();
            if (!(_cb.IsEmpty() || _cb->IsNull() || _cb->IsUndefined())) {
                this->cb->SetFunction(_cb);
            }
            this->wrapped->Ref();
            this->uv_work.data = this;
        }

        virtual ~EIOCmdTask() {
            delete this->cb;
            this->wrapped->Unref();
            if (this->free_cmd_data) {
                this->free_cmd_data(this);
            }
        }
    };
}








#endif	/* EJDB_CMD_H */

