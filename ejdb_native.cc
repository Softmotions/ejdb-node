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

#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <node_object_wrap.h>
#include <ejdb_private.h>

#include "ejdb_args.h"
#include "ejdb_cmd.h"
#include "ejdb_logging.h"
#include "ejdb_thread.h"

#include <math.h>
#include <vector>
#include <sstream>
#include <locale.h>
#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER
#include <unordered_set>
#else
#include <ext/hash_set>
#ifdef __GNUC__

using namespace __gnu_cxx;
#endif
#endif

using namespace node;
using namespace v8;

static const int CMD_RET_ERROR = 1;

#define DEFINE_INT64_CONSTANT(target, constant)                     \
  (target)->Set(NanNew<String>(#constant),                          \
                NanNew<Number>((int64_t) constant),                 \
                static_cast<PropertyAttribute>(ReadOnly|DontDelete))

namespace ejdb {

    ///////////////////////////////////////////////////////////////////////////
    //                           Some symbols                                //
    ///////////////////////////////////////////////////////////////////////////

    static Eternal<String> sym_large;
    static Eternal<String> sym_compressed;
    static Eternal<String> sym_records;
    static Eternal<String> sym_cachedrecords;
    static Eternal<String> sym_explain;
    static Eternal<String> sym_merge;

    static Eternal<String> sym_name;
    static Eternal<String> sym_iname;
    static Eternal<String> sym_field;
    static Eternal<String> sym_indexes;
    static Eternal<String> sym_options;
    static Eternal<String> sym_file;
    static Eternal<String> sym_buckets;
    static Eternal<String> sym_type;


    ///////////////////////////////////////////////////////////////////////////
    //                             Fetch functions                           //
    ///////////////////////////////////////////////////////////////////////////

    enum eFetchStatus {
        FETCH_NONE,
        FETCH_DEFAULT,
        FETCH_VAL
    };

    char* fetch_string_data(Handle<Value> sobj, eFetchStatus* fs, const char* def) {
        NanScope();
        if (sobj->IsNull() || sobj->IsUndefined()) {
            if (fs) {
                *fs = FETCH_DEFAULT;
            }
            return def ? strdup(def) : strdup("");
        }
        NanUtf8String value(sobj);
        const char* data = *value;
        if (fs) {
            *fs = FETCH_VAL;
        }
        return data ? strdup(data) : strdup("");
    }

    int64_t fetch_int_data(Handle<Value> sobj, eFetchStatus* fs, int64_t def) {
        NanScope();
        if (!(sobj->IsNumber() || sobj->IsInt32() || sobj->IsUint32())) {
            if (fs) {
                *fs = FETCH_DEFAULT;
            }
            return def;
        }
        if (fs) {
            *fs = FETCH_VAL;
        }
        return sobj->ToNumber()->IntegerValue();
    }

    bool fetch_bool_data(Handle<Value> sobj, eFetchStatus* fs, bool def) {
        NanScope();
        if (sobj->IsNull() || sobj->IsUndefined()) {
            if (fs) {
                *fs = FETCH_DEFAULT;
            }
            return def;
        }
        if (fs) {
            *fs = FETCH_VAL;
        }
        return sobj->BooleanValue();
    }

    double fetch_real_data(Handle<Value> sobj, eFetchStatus* fs, double def) {
        NanScope();
        if (!(sobj->IsNumber() || sobj->IsInt32())) {
            if (fs) {
                *fs = FETCH_DEFAULT;
            }
            return def;
        }
        if (fs) {
            *fs = FETCH_VAL;
        }
        return sobj->ToNumber()->NumberValue();
    }

	struct V8ObjHash {

        size_t operator()(const Handle<Object>& obj) const {
            return (size_t) obj->GetIdentityHash();
        }
    };
    struct V8ObjEq {

        bool operator()(const Handle<Object>& o1, const Handle<Object>& o2) const {
            return (o1 == o2);
        }
    };

#ifdef _MSC_VER
	typedef std::unordered_set<Handle<Object>, V8ObjHash, V8ObjEq> V8ObjSet;
#else
    typedef hash_set<Handle<Object>, V8ObjHash, V8ObjEq> V8ObjSet;
#endif


    struct TBSONCTX {
        V8ObjSet tset; //traversed objects set
        int nlevel;
        bool inquery;

        TBSONCTX() : nlevel(0), inquery(false) {
        }
    };

    static Handle<Object> toV8Object(bson_iterator *it, bson_type obt = BSON_OBJECT);
    static Handle<Value> toV8Value(bson_iterator *it);
    static void toBSON0(Handle<Object> obj, bson *bs, TBSONCTX *ctx);

    static Handle<Value> toV8Value(bson_iterator *it) {
        NanEscapableScope();
        bson_type bt = bson_iterator_type(it);

        switch (bt) {
            case BSON_OID:
            {
                char xoid[25];
                bson_oid_to_string(bson_iterator_oid(it), xoid);
                return NanEscapeScope(NanNew<String>(xoid));
            }
            case BSON_STRING:
            case BSON_SYMBOL:
                return NanEscapeScope(NanNew<String>(bson_iterator_string(it), bson_iterator_string_len(it) - 1));
            case BSON_NULL:
                return NanNull();
            case BSON_UNDEFINED:
                return NanUndefined();
            case BSON_INT:
                return NanEscapeScope(NanNew<Integer>(bson_iterator_int_raw(it)));
            case BSON_LONG:
                return NanEscapeScope(NanNew<Number>(bson_iterator_long_raw(it)));
            case BSON_DOUBLE:
                return NanEscapeScope(NanNew<Number>(bson_iterator_double_raw(it)));
            case BSON_BOOL:
                return NanEscapeScope(NanNew<Boolean>(bson_iterator_bool_raw(it) ? true : false));
            case BSON_OBJECT:
            case BSON_ARRAY:
            {
                bson_iterator nit;
                bson_iterator_subiterator(it, &nit);    
                return NanEscapeScope(toV8Object(&nit, bt));
            }
            case BSON_DATE:
                return NanEscapeScope(NanNew<Date>((double) bson_iterator_date(it)));
            case BSON_BINDATA:
                //TODO test it!
                return NanEscapeScope(NanNewBufferHandle(bson_iterator_bin_data(it), bson_iterator_bin_len(it)));
            case BSON_REGEX:
            {
                const char *re = bson_iterator_regex(it);
                const char *ro = bson_iterator_regex_opts(it);
                int rflgs = RegExp::kNone;
                for (int i = ((int) strlen(ro) - 1); i >= 0; --i) {
                    if (ro[i] == 'i') {
                        rflgs |= RegExp::kIgnoreCase;
                    } else if (ro[i] == 'g') {
                        rflgs |= RegExp::kGlobal;
                    } else if (ro[i] == 'm') {
                        rflgs |= RegExp::kMultiline;
                    }
                }
                return NanEscapeScope(NanNew<RegExp>(NanNew<String>(re), (RegExp::Flags) rflgs));
            }
            default:
                break;
        }
        return NanUndefined();
    }

    static Handle<Object> toV8Object(bson_iterator *it, bson_type obt) {
        NanEscapableScope();
        Local<Object> ret;
        uint32_t knum = 0;
        if (obt == BSON_ARRAY) {
            ret = NanNew<Array>();
        } else if (obt == BSON_OBJECT) {
            ret = NanNew<Object>();
        } else {
            assert(0);
        }
        bson_type bt;
        while ((bt = bson_iterator_next(it)) != BSON_EOO) {
            const char *key = bson_iterator_key(it);
            if (obt == BSON_ARRAY) {
                knum = (uint32_t) tcatoi(key);
            }
            switch (bt) {
                case BSON_OID:
                {
                    char xoid[25];
                    bson_oid_to_string(bson_iterator_oid(it), xoid);
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<String>(xoid, 24));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<String>(xoid, 24));
                    }
                    break;
                }
                case BSON_STRING:
                case BSON_SYMBOL:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<String>(bson_iterator_string(it), bson_iterator_string_len(it) - 1));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<String>(bson_iterator_string(it), bson_iterator_string_len(it) - 1));
                    }
                    break;
                case BSON_NULL:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNull());
                    } else {
                        ret->Set(NanNew<String>(key), NanNull());
                    }
                    break;
                case BSON_UNDEFINED:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanUndefined());
                    } else {
                        ret->Set(NanNew<String>(key), NanUndefined());
                    }
                    break;
                case BSON_INT:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<Integer>(bson_iterator_int_raw(it)));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<Integer>(bson_iterator_int_raw(it)));
                    }
                    break;
                case BSON_LONG:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<Number>((double) bson_iterator_long_raw(it)));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<Number>((double) bson_iterator_long_raw(it)));
                    }
                    break;
                case BSON_DOUBLE:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<Number>(bson_iterator_double_raw(it)));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<Number>(bson_iterator_double_raw(it)));
                    }
                    break;
                case BSON_BOOL:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, bson_iterator_bool_raw(it) ? NanTrue() : NanFalse());
                    } else {
                        ret->Set(NanNew<String>(key), bson_iterator_bool_raw(it) ? NanTrue() : NanFalse());
                    }
                    break;
                case BSON_OBJECT:
                case BSON_ARRAY:
                {
                    bson_iterator nit;
                    bson_iterator_subiterator(it, &nit);
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, toV8Object(&nit, bt));
                    } else {
                        ret->Set(NanNew<String>(key), toV8Object(&nit, bt));
                    }
                    break;
                }
                case BSON_DATE:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<Date>((double) bson_iterator_date(it)));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<Date>((double) bson_iterator_date(it)));
                    }
                    break;
                case BSON_BINDATA:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNewBufferHandle(bson_iterator_bin_data(it), bson_iterator_bin_len(it)));
                    } else {
                        ret->Set(NanNew<String>(key), NanNewBufferHandle(bson_iterator_bin_data(it), bson_iterator_bin_len(it)));
                    }
                    break;
                case BSON_REGEX:
                {
                    const char *re = bson_iterator_regex(it);
                    const char *ro = bson_iterator_regex_opts(it);
                    int rflgs = RegExp::kNone;
                    for (int i = ((int) strlen(ro) - 1); i >= 0; --i) {
                        if (ro[i] == 'i') {
                            rflgs |= RegExp::kIgnoreCase;
                        } else if (ro[i] == 'g') {
                            rflgs |= RegExp::kGlobal;
                        } else if (ro[i] == 'm') {
                            rflgs |= RegExp::kMultiline;
                        }
                    }
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanNew<RegExp>(NanNew<String>(re), (RegExp::Flags) rflgs));
                    } else {
                        ret->Set(NanNew<String>(key), NanNew<RegExp>(NanNew<String>(re), (RegExp::Flags) rflgs));
                    }
                    break;
                }
                default:
                    if (obt == BSON_ARRAY) {
                        ret->Set(knum, NanUndefined());
                    } else {
                        ret->Set(NanNew<String>(key), NanUndefined());
                    }
                    break;
            }
        }
        return NanEscapeScope(ret);
    }

    static void toBSON0(Handle<Object> obj, bson *bs, TBSONCTX *ctx) {
        NanScope();
        assert(ctx && obj->IsObject());
        V8ObjSet::iterator it = ctx->tset.find(obj);
        if (it != ctx->tset.end()) {
            bs->err = BSON_ERROR_ANY;
            bs->errstr = strdup("Converting circular structure to JSON");
            return;
        }
        ctx->nlevel++;
        ctx->tset.insert(obj);
        Local<Array> pnames = obj->GetOwnPropertyNames();
        for (uint32_t i = 0; i < pnames->Length(); ++i) {
            if (bs->err) {
                break;
            }
            Local<Value> pn = pnames->Get(i);
            String::Utf8Value spn(pn);
            Local<Value> pv = obj->Get(pn);

            if (!ctx->inquery && ctx->nlevel == 1 && !strcmp(JDBIDKEYNAME, *spn)) { //top level _id key
                if (pv->IsNull() || pv->IsUndefined()) { //skip _id addition for null or undefined vals
                    continue;
                }
                String::Utf8Value idv(pv->ToString());
                if (ejdbisvalidoidstr(*idv)) {
                    bson_oid_t oid;
                    bson_oid_from_string(&oid, *idv);
                    bson_append_oid(bs, JDBIDKEYNAME, &oid);
                } else {
                    bs->err = BSON_ERROR_ANY;
                    bs->errstr = strdup("Invalid bson _id field value");
                    break;
                }
            }
            if (pv->IsString()) {
                String::Utf8Value val(pv);
                bson_append_string(bs, *spn, *val);
            } else if (pv->IsInt32()) {
                bson_append_int(bs, *spn, pv->Int32Value());
            } else if (pv->IsUint32()) {
                bson_append_long(bs, *spn, pv->Uint32Value());
            } else if (pv->IsNumber()) {
                double nv = pv->NumberValue();
                double ipart;
                if (modf(nv, &ipart) == 0.0) {
                    bson_append_long(bs, *spn, pv->IntegerValue());
                } else {
                    bson_append_double(bs, *spn, nv);
                }
            } else if (pv->IsNull()) {
                bson_append_null(bs, *spn);
            } else if (pv->IsUndefined()) {
                bson_append_undefined(bs, *spn);
            } else if (pv->IsBoolean()) {
                bson_append_bool(bs, *spn, pv->BooleanValue());
            } else if (pv->IsDate()) {
                bson_append_date(bs, *spn, Handle<Date>::Cast(pv)->IntegerValue());
            } else if (pv->IsRegExp()) {
                Handle<RegExp> regexp = Handle<RegExp>::Cast(pv);
                int flags = regexp->GetFlags();
                String::Utf8Value sr(regexp->GetSource());
                std::string sf;
                if (flags & RegExp::kIgnoreCase) {
                    sf.append("i");
                }
                if (flags & RegExp::kGlobal) {
                    sf.append("g");
                }
                if (flags & RegExp::kMultiline) {
                    sf.append("m");
                }
                bson_append_regex(bs, *spn, *sr, sf.c_str());
            } else if (Buffer::HasInstance(pv)) {
                bson_append_binary(bs, *spn, BSON_BIN_BINARY,
                        Buffer::Data(Handle<Object>::Cast(pv)),
                        (int) Buffer::Length(Handle<Object>::Cast(pv)));
            } else if (pv->IsObject() || pv->IsArray()) {
                if (pv->IsArray()) {
                    bson_append_start_array(bs, *spn);
                } else {
                    bson_append_start_object(bs, *spn);
                }
                toBSON0(Handle<Object>::Cast(pv), bs, ctx);
                if (bs->err) {
                    break;
                }
                if (pv->IsArray()) {
                    bson_append_finish_array(bs);
                } else {
                    bson_append_finish_object(bs);
                }
            }
        }
        ctx->nlevel--;
        it = ctx->tset.find(obj);
        if (it != ctx->tset.end()) {
            ctx->tset.erase(it);
        }
    }

    /** Convert V8 object into binary json instance. After usage, it must be freed by bson_del() */
    static void toBSON(Handle<Object> obj, bson *bs, bool inquery) {
        NanScope();
        TBSONCTX ctx;
        ctx.inquery = inquery;
        toBSON0(obj, bs, &ctx);
    }

    class NodeEJDBCursor;
    class NodeEJDB;

    ///////////////////////////////////////////////////////////////////////////
    //                          Main NodeEJDB                                //
    ///////////////////////////////////////////////////////////////////////////

    class NodeEJDB : public ObjectWrap {

        enum { //Commands
            cmdSave = 1, //Save JSON object
            cmdLoad = 2, //Load BSON by oid
            cmdRemove = 3, //Remove BSON by oid
            cmdQuery = 4, //Query collection
            cmdRemoveColl = 5, //Remove collection
            cmdSetIndex = 6, //Set index
            cmdSync = 7, //Sync database
            cmdTxBegin = 8, //Begin collection transaction
            cmdTxAbort = 9, //Abort collection transaction
            cmdTxCommit = 10, //Commit collection transaction
            cmdTxStatus = 11, //Get collection transaction status
            cmdCmd = 12, //Execute EJDB command
            cmdOpen = 13, //Open database
            cmdClose = 14, //Close database
            cmdEnsure = 15 //Ensure collection
        };

        struct BSONCmdData { //Any bson related cmd data
            std::string cname; //Name of collection
            std::vector<bson*> bsons; //bsons to save|query
            std::vector<bson_oid_t> ids; //saved updated oids
            bson_oid_t ref; //Bson ref
            bool merge; //Merge bson on save

            BSONCmdData(const char* _cname) : cname(_cname), merge(false) {
                memset(&ref, 0, sizeof (ref));
            }

            virtual ~BSONCmdData() {
                std::vector<bson*>::iterator it;
                for (it = bsons.begin(); it < bsons.end(); it++) {
                    bson *bs = *(it);
                    if (bs) bson_del(bs);
                }
            }
        };

        struct BSONQCmdData : public BSONCmdData { //Query cmd data
            TCLIST *res;
            int qflags;
            uint32_t count;
            TCXSTR *log;

            BSONQCmdData(const char *_cname, int _qflags) :
            BSONCmdData(_cname), res(NULL), qflags(_qflags), count(0), log(NULL) {
            }

            virtual ~BSONQCmdData() {
                if (res) {
                    tclistdel(res);
                }
                if (log) {
                    tcxstrdel(log);
                }

            }
        };

        struct RMCollCmdData { //Remove collection command data
            std::string cname; //Name of collection
            bool prune;

            RMCollCmdData(const char* _cname, bool _prune) : cname(_cname), prune(_prune) {
            }
        };

        struct SetIndexCmdData { //Set index command data
            std::string cname; //Name of collection
            std::string ipath; //JSON field path for index
            int flags; //set index op flags

            SetIndexCmdData(const char *_cname, const char *_ipath, int _flags) :
            cname(_cname), ipath(_ipath), flags(_flags) {
            }
        };

        struct TxCmdData { //Transaction control command data
            std::string cname; //Name of collection
            bool txactive; //If true we are in transaction

            TxCmdData(const char *_name) : cname(_name), txactive(false) {

            }
        };

        struct OpenCmdData { //Open database command data
            std::string path; //Path to database
            int mode; //Open mode

            OpenCmdData(const char *_path, int _mode) :
            path(_path), mode(_mode) {
            }
        };

        struct EnsureCmdData { //Ensure collection command data
            std::string cname; //Name of collection
            EJCOLLOPTS jcopts; //Collection options

            EnsureCmdData(const char *_cname, EJCOLLOPTS _jcopts) :
            cname(_cname), jcopts(_jcopts) {
            }
        };

        typedef EIOCmdTask<NodeEJDB> EJBTask; //Most generic task
        typedef EIOCmdTask<NodeEJDB, BSONCmdData> BSONCmdTask; //Any bson related task
        typedef EIOCmdTask<NodeEJDB, BSONQCmdData> BSONQCmdTask; //Query task
        typedef EIOCmdTask<NodeEJDB, RMCollCmdData> RMCollCmdTask; //Remove collection
        typedef EIOCmdTask<NodeEJDB, SetIndexCmdData> SetIndexCmdTask; //Set index command
        typedef EIOCmdTask<NodeEJDB, TxCmdData> TxCmdTask; //Transaction control command
        typedef EIOCmdTask<NodeEJDB, OpenCmdData> OpenCmdTask; //Open db task
        typedef EIOCmdTask<NodeEJDB, EnsureCmdData> EnsureCmdTask; //Ensure collection task

        static Persistent<FunctionTemplate> constructor_template;

        EJDB *m_jb;

        static void s_exec_cmd_eio(uv_work_t *req) {
            EJBTask *task = (EJBTask*) (req->data);
            NodeEJDB *njb = task->wrapped;
            assert(njb);
            njb->exec_cmd(task);
        }

        static void s_exec_cmd_eio_after(uv_work_t *req) {
            EJBTask *task = (EJBTask*) (req->data);
            NodeEJDB *njb = task->wrapped;
            assert(njb);
            njb->exec_cmd_after(task);
            delete task;
        }

        static NAN_METHOD(s_new_object) {
            NanEscapableScope();
            NodeEJDB *njb = new NodeEJDB();
            njb->Wrap(args.This());
            NanReturnThis();
        }

        static NAN_METHOD(s_open) {
            NanEscapableScope();
            Local<Function> cb;
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            REQ_STR_ARG(0, dbPath);
            REQ_INT32_ARG(1, mode);
            OpenCmdData *cmdata = new OpenCmdData(*dbPath, mode);
            if (args[2]->IsFunction()) {
                cb = Local<Function>::Cast(args[2]);
                OpenCmdTask *task = new OpenCmdTask(cb, njb, cmdOpen, cmdata, OpenCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();//return NanUndefined();
            } else {
                OpenCmdTask task(cb, njb, cmdOpen, cmdata, OpenCmdTask::delete_val);
                njb->open(&task);
                NanReturnValue(njb->open_after(&task));
            }
        }

        static NAN_METHOD(s_close) {
            NanEscapableScope();
            Local<Function> cb;
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (args[0]->IsFunction()) {
                cb = Local<Function>::Cast(args[0]);
                EJBTask *task = new EJBTask(cb, njb, cmdClose, NULL, NULL);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();//return NanUndefined();
            } else {
                EJBTask task(cb, njb, cmdClose, NULL, NULL);
                njb->close(&task);
                NanReturnValue(njb->close_after(&task));
            }
        }

        static NAN_METHOD(s_load) {
            NanEscapableScope();
            REQ_ARGS(2);
            REQ_STR_ARG(0, cname); //Collection name
            REQ_STR_ARG(1, soid); //String OID
            if (!ejdbisvalidoidstr(*soid)) {
                return NanThrowError("Argument 2: Invalid OID string");
            }
            Local<Function> cb;
            bson_oid_t oid;
            bson_oid_from_string(&oid, *soid);
            BSONCmdData *cmdata = new BSONCmdData(*cname);
            cmdata->ref = oid;

            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (args[2]->IsFunction()) {
                cb = Local<Function>::Cast(args[2]);
                BSONCmdTask *task = new BSONCmdTask(cb, njb, cmdLoad, cmdata, BSONCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                BSONCmdTask task(cb, njb, cmdLoad, cmdata, BSONCmdTask::delete_val);
                njb->load(&task);
                NanReturnValue(njb->load_after(&task));
            }
        }

        static NAN_METHOD(s_remove) {
            NanEscapableScope();
            REQ_ARGS(2);
            REQ_STR_ARG(0, cname); //Collection name
            REQ_STR_ARG(1, soid); //String OID
            if (!ejdbisvalidoidstr(*soid)) {
                return NanThrowError("Argument 2: Invalid OID string");
            }
            Local<Function> cb;
            bson_oid_t oid;
            bson_oid_from_string(&oid, *soid);
            BSONCmdData *cmdata = new BSONCmdData(*cname);
            cmdata->ref = oid;

            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (args[2]->IsFunction()) {
                cb = Local<Function>::Cast(args[2]);
                BSONCmdTask *task = new BSONCmdTask(cb, njb, cmdRemove, cmdata, BSONCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                BSONCmdTask task(cb, njb, cmdRemove, cmdata, BSONCmdTask::delete_val);
                njb->remove(&task);
                NanReturnValue(njb->remove_after(&task));
            }
        }

        static NAN_METHOD(s_save) {
            NanEscapableScope();
            REQ_ARGS(3);
            REQ_STR_ARG(0, cname); //Collection name
            REQ_ARR_ARG(1, oarr); //Array of JSON objects
            REQ_OBJ_ARG(2, opts); //Options obj

            Local<Function> cb;
            BSONCmdData *cmdata = new BSONCmdData(*cname);
            for (uint32_t i = 0; i < oarr->Length(); ++i) {
                Local<Value> v = oarr->Get(i);
                if (!v->IsObject()) {
                    cmdata->bsons.push_back(NULL);
                    continue;
                }
                bson *bs = bson_create();
                assert(bs);
                bson_init(bs);
                toBSON(Handle<Object>::Cast(v), bs, false);
                if (bs->err) {
                    Local<String> msg = NanNew<String>(bson_first_errormsg(bs));
                    bson_del(bs);
                    delete cmdata;
                    return NanThrowError(msg);
                }
                bson_finish(bs);
                cmdata->bsons.push_back(bs);
            }
            if (opts->Get(sym_merge.Get(Isolate::GetCurrent()))->BooleanValue()) {
                cmdata->merge = true;
            }
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());

            if (args[3]->IsFunction()) { //callback provided
                cb = Local<Function>::Cast(args[3]);
                BSONCmdTask *task = new BSONCmdTask(cb, njb, cmdSave, cmdata, BSONCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                BSONCmdTask task(cb, njb, cmdSave, cmdata, BSONCmdTask::delete_val);
                njb->save(&task);
                NanReturnValue(njb->save_after(&task));
            }
        }

        static NAN_METHOD(s_cmd) {
            NanEscapableScope();
            REQ_ARGS(1);
            REQ_OBJ_ARG(0, cmdobj);

            Local<Function> cb;
            BSONQCmdData *cmdata = new BSONQCmdData("", 0);
            bson *bs = bson_create();
            bson_init_as_query(bs);
            toBSON(cmdobj, bs, false);
            if (bs->err) {
                Local<String> msg = NanNew<String>(bson_first_errormsg(bs));
                bson_del(bs);
                delete cmdata;
                return NanThrowError(msg);
            }
            bson_finish(bs);
            cmdata->bsons.push_back(bs);
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (args[1]->IsFunction()) { //callback provided
                cb = Local<Function>::Cast(args[1]);
                BSONQCmdTask *task = new BSONQCmdTask(cb, njb, cmdCmd, cmdata, BSONQCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                BSONQCmdTask task(cb, njb, cmdCmd, cmdata, BSONQCmdTask::delete_val);
                njb->ejdbcmd(&task);
                NanReturnValue(njb->ejdbcmd_after(&task));
            }
        }

        static NAN_METHOD(s_query) {
            NanEscapableScope();
            REQ_ARGS(3);
            REQ_STR_ARG(0, cname)
            REQ_ARR_ARG(1, qarr);
            REQ_INT32_ARG(2, qflags);

            if (qarr->Length() == 0) {
                return NanThrowError("Query array must have at least one element");
            }
            Local<Function> cb;
            BSONQCmdData *cmdata = new BSONQCmdData(*cname, qflags);
            uint32_t len = qarr->Length();
            for (uint32_t i = 0; i < len; ++i) {
                Local<Value> qv = qarr->Get(i);
                if (i > 0 && i == len - 1 && (qv->IsNull() || qv->IsUndefined())) { //Last hints element can be NULL
                    cmdata->bsons.push_back(NULL);
                    continue;
                } else if (!qv->IsObject()) {
                    delete cmdata;
                    return NanThrowError("Each element of query array must be an object (except last hints element)");
                }
                bson *bs = bson_create();
                bson_init_as_query(bs);
                toBSON(Local<Object>::Cast(qv), bs, true);
                bson_finish(bs);
                if (bs->err) {
                    Local<String> msg = NanNew<String>(bson_first_errormsg(bs));
                    bson_del(bs);
                    delete cmdata;
                    return NanThrowError(msg);
                }
                cmdata->bsons.push_back(bs);
            }
            
            if (len > 1 && qarr->Get(len - 1)->IsObject()) {
                Local<Object> hints = Local<Object>::Cast(qarr->Get(len - 1));
                if (hints->Get(sym_explain.Get(Isolate::GetCurrent()))->BooleanValue()) {
                    cmdata->log = tcxstrnew();
                }
            }

            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());

            if (args[3]->IsFunction()) { //callback provided
                cb = Local<Function>::Cast(args[3]);
                BSONQCmdTask *task = new BSONQCmdTask(cb, njb, cmdQuery, cmdata, BSONQCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                BSONQCmdTask task(cb, njb, cmdQuery, cmdata, BSONQCmdTask::delete_val);
                njb->query(&task);
                NanReturnValue(njb->query_after(&task));
            }
        }

        static NAN_METHOD(s_set_index) {
            NanEscapableScope();
            REQ_ARGS(3);
            REQ_STR_ARG(0, cname)
            REQ_STR_ARG(1, ipath)
            REQ_INT32_ARG(2, flags);

            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            SetIndexCmdData *cmdata = new SetIndexCmdData(*cname, *ipath, flags);

            Local<Function> cb;
            if (args[3]->IsFunction()) {
                cb = Local<Function>::Cast(args[3]);
                SetIndexCmdTask *task = new SetIndexCmdTask(cb, njb, cmdSetIndex, cmdata, SetIndexCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
            } else {
                SetIndexCmdTask task(cb, njb, cmdSetIndex, cmdata, SetIndexCmdTask::delete_val);
                njb->set_index(&task);
                njb->set_index_after(&task);
                if (task.cmd_ret) {
                    return NanThrowError(task.cmd_ret_msg.c_str());
                }
            }
            NanReturnUndefined();
        }

        static NAN_METHOD(s_sync) {
            NanEscapableScope();
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            Local<Function> cb;
            if (args[0]->IsFunction()) {
                cb = Local<Function>::Cast(args[0]);
                EJBTask *task = new EJBTask(cb, njb, cmdSync, NULL, NULL);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
            } else {
                EJBTask task(cb, njb, cmdSync, NULL, NULL);
                njb->sync(&task);
                njb->sync_after(&task);
                if (task.cmd_ret) {
                    return NanThrowError(task.cmd_ret_msg.c_str());
                }
            }
            NanReturnUndefined();
        }

        static NAN_METHOD(s_db_meta) {
            NanEscapableScope();
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (!ejdbisopen(njb->m_jb)) {
                return NanThrowError("Operation on closed EJDB instance");
            }
            bson *meta = ejdbmeta(njb->m_jb);
            if (!meta) {
                return NanThrowError(njb->_jb_error_msg());
            }
            bson_iterator it;
            bson_iterator_init(&it, meta);
            Handle<Object> ret = toV8Object(&it);
            bson_del(meta);
            NanReturnValue(ret);
        }

        //transaction control handlers

        static NAN_METHOD(s_coll_txctl) {
            NanEscapableScope();
            REQ_STR_ARG(0, cname);
            //operation values:
            //cmdTxBegin = 8, //Begin collection transaction
            //cmdTxAbort = 9, //Abort collection transaction
            //cmdTxCommit = 10, //Commit collection transaction
            //cmdTxStatus = 11 //Get collection transaction status
            REQ_INT32_ARG(1, op);
            //Arg 2 is the optional function callback arg
            if (!(op == cmdTxBegin ||
                    op == cmdTxAbort ||
                    op == cmdTxCommit ||
                    op == cmdTxStatus)) {
                return NanThrowTypeError("Invalid value of 1 argument");
            }
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            assert(njb);
            EJDB *jb = njb->m_jb;
            if (!ejdbisopen(jb)) {
                return NanThrowError("Operation on closed EJDB instance");
            }
            TxCmdData *cmdata = new TxCmdData(*cname);
            Local<Function> cb;
            if (args[2]->IsFunction()) {
                cb = Local<Function>::Cast(args[2]);
                TxCmdTask *task = new TxCmdTask(cb, njb, op, cmdata, TxCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                TxCmdTask task(cb, njb, op, cmdata, NULL);
                njb->txctl(&task);
                NanReturnValue(njb->txctl_after(&task));
            }
        }

        static NAN_METHOD(s_ecode) {
            NanEscapableScope();
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (!njb->m_jb) { //not using ejdbisopen()
                return NanThrowError("Operation on closed EJDB instance");
            }
            NanReturnValue(NanNew<Integer>(ejdbecode(njb->m_jb)));
        }

        static NAN_METHOD(s_ensure_collection) {
            NanEscapableScope();
            Local<Function> cb;
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            REQ_STR_ARG(0, cname);
            REQ_OBJ_ARG(1, copts);
            EJCOLLOPTS jcopts;
            memset(&jcopts, 0, sizeof (jcopts));
            
            // TODO: constants
            jcopts.cachedrecords = (int) fetch_int_data(copts->Get(sym_cachedrecords.Get(Isolate::GetCurrent())), NULL, 0);
            jcopts.compressed = fetch_bool_data(copts->Get(sym_compressed.Get(Isolate::GetCurrent())), NULL, false);
            jcopts.large = fetch_bool_data(copts->Get(sym_large.Get(Isolate::GetCurrent())), NULL, false);
            jcopts.records = fetch_int_data(copts->Get(sym_records.Get(Isolate::GetCurrent())), NULL, 0);
            EnsureCmdData *cmdata = new EnsureCmdData(*cname, jcopts);
            if (args[2]->IsFunction()) {
                cb = Local<Function>::Cast(args[2]);
                EnsureCmdTask *task = new EnsureCmdTask(cb, njb, cmdEnsure, cmdata, EnsureCmdTask::delete_val);
                uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
                NanReturnUndefined();
            } else {
                EnsureCmdTask task(cb, njb, cmdEnsure, cmdata, EnsureCmdTask::delete_val);
                njb->ensure(&task);
                NanReturnValue(njb->ensure_after(&task));
            }

            if (!ejdbisopen(njb->m_jb)) {
                return NanThrowError("Operation on closed EJDB instance");
            }
            EJCOLL *coll = ejdbcreatecoll(njb->m_jb, *cname, &jcopts);
            if (!coll) {
                return NanThrowError(njb->_jb_error_msg());
            }
        }

        static NAN_METHOD(s_rm_collection) {
            NanEscapableScope();
            REQ_STR_ARG(0, cname);
            REQ_VAL_ARG(1, prune);
            REQ_FUN_ARG(2, cb);
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            if (!ejdbisopen(njb->m_jb)) {
                return NanThrowError("Operation on closed EJDB instance");
            }
            RMCollCmdData *cmdata = new RMCollCmdData(*cname, prune->BooleanValue());
            RMCollCmdTask *task = new RMCollCmdTask(cb, njb, cmdRemoveColl, cmdata, RMCollCmdTask::delete_val);
            uv_queue_work(uv_default_loop(), &task->uv_work, s_exec_cmd_eio, (uv_after_work_cb)s_exec_cmd_eio_after);
            NanReturnUndefined();
        }

        static NAN_METHOD(s_is_open) {
            NanEscapableScope();
            NodeEJDB *njb = ObjectWrap::Unwrap< NodeEJDB > (args.This());
            NanReturnValue(NanNew<Boolean>(ejdbisopen(njb->m_jb)));
        }


        ///////////////////////////////////////////////////////////////////////////
        //                            Instance methods                           //
        ///////////////////////////////////////////////////////////////////////////

        void exec_cmd(EJBTask *task) {
            int cmd = task->cmd;
            switch (cmd) {
                case cmdQuery:
                    query((BSONQCmdTask*) task);
                    break;
                case cmdLoad:
                    load((BSONCmdTask*) task);
                    break;
                case cmdSave:
                    save((BSONCmdTask*) task);
                    break;
                case cmdRemove:
                    remove((BSONCmdTask*) task);
                    break;
                case cmdRemoveColl:
                    rm_collection((RMCollCmdTask*) task);
                    break;
                case cmdSetIndex:
                    set_index((SetIndexCmdTask*) task);
                    break;
                case cmdSync:
                    sync(task);
                    break;
                case cmdTxBegin:
                case cmdTxCommit:
                case cmdTxAbort:
                case cmdTxStatus:
                    txctl((TxCmdTask*) task);
                    break;
                case cmdCmd:
                    ejdbcmd((BSONQCmdTask*) task);
                    break;
                case cmdOpen:
                    open((OpenCmdTask*) task);
                    break;
                case cmdClose:
                    close(task);
                    break;
                case cmdEnsure:
                    ensure((EnsureCmdTask*) task);
                    break;
                default:
                    assert(0);
            }
        }

        void exec_cmd_after(EJBTask *task) {
            int cmd = task->cmd;
            switch (cmd) {
                case cmdQuery:
                    query_after((BSONQCmdTask*) task);
                    break;
                case cmdLoad:
                    load_after((BSONCmdTask*) task);
                    break;
                case cmdSave:
                    save_after((BSONCmdTask*) task);
                    break;
                case cmdRemove:
                    remove_after((BSONCmdTask*) task);
                    break;
                case cmdRemoveColl:
                    rm_collection_after((RMCollCmdTask*) task);
                    break;
                case cmdSetIndex:
                    set_index_after((SetIndexCmdTask*) task);
                    break;
                case cmdSync:
                    sync_after(task);
                    break;
                case cmdTxBegin:
                case cmdTxCommit:
                case cmdTxAbort:
                case cmdTxStatus:
                    txctl_after((TxCmdTask*) task);
                    break;
                case cmdCmd:
                    ejdbcmd_after((BSONQCmdTask*) task);
                    break;
                case cmdOpen:
                    open_after((OpenCmdTask*) task);
                    break;
                case cmdClose:
                    close_after(task);
                    break;
                case cmdEnsure:
                    ensure_after((EnsureCmdTask*) task);
                    break;
                default:
                    assert(0);
            }
        }

        void sync(EJBTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            if (!ejdbsyncdb(m_jb)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
            }
        }

        void sync_after(EJBTask *task) {
            NanScope();
            Local<Value> argv[1];
            if (task->cb->IsEmpty()) {
                return;
            }
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
        }

        void set_index(SetIndexCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            SetIndexCmdData *cmdata = task->cmd_data;
            assert(cmdata);

            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }
            if (!ejdbsetindex(coll, cmdata->ipath.c_str(), cmdata->flags)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
            }
        }

        void set_index_after(SetIndexCmdTask *task) {
            NanScope();
            Local<Value> argv[1];
            if (task->cb->IsEmpty()) {
                return;
            }
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
        }

        void rm_collection(RMCollCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            RMCollCmdData *cmdata = task->cmd_data;
            assert(cmdata);
            if (!ejdbrmcoll(m_jb, cmdata->cname.c_str(), cmdata->prune)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
            }
        }

        void rm_collection_after(RMCollCmdTask *task) {
            NanScope();
            Local<Value> argv[1];
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
        }

        void remove(BSONCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            BSONCmdData *cmdata = task->cmd_data;
            assert(cmdata);
            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }
            if (!ejdbrmbson(coll, &task->cmd_data->ref)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
            }
        }

        Handle<Value> remove_after(BSONCmdTask *task) {
            NanEscapableScope();
            Local<Value> argv[1];
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            if (task->cb->IsEmpty()) {
                if (task->cmd_ret != 0) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                } else
                    return NanUndefined();
            } else {
                TryCatch try_catch;
                task->cb->Call(1, argv);
                if (try_catch.HasCaught()) {
                    FatalException(try_catch);
                }
                return NanUndefined();
            }
        }

        void txctl(TxCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            TxCmdData *cmdata = task->cmd_data;
            assert(cmdata);

            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }
            bool ret = false;
            switch (task->cmd) {
                case cmdTxBegin:
                    ret = ejdbtranbegin(coll);
                    break;
                case cmdTxCommit:
                    ret = ejdbtrancommit(coll);
                    break;
                case cmdTxAbort:
                    ret = ejdbtranabort(coll);
                    break;
                case cmdTxStatus:
                    ret = ejdbtranstatus(coll, &(cmdata->txactive));
                    break;
                default:
                    assert(0);
            }
            if (!ret) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
            }
        }

        Handle<Value> txctl_after(TxCmdTask *task) {
            NanEscapableScope();
            TxCmdData *cmdata = task->cmd_data;
            int args = 1;
            Local<Value> argv[2];
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
                if (task->cmd == cmdTxStatus) {
                    argv[1] = NanNew<Boolean>(cmdata->txactive);
                    args = 2;
                }
            }
            if (task->cb->IsEmpty()) {
                if (task->cmd_ret != 0) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                } else {
                    if (task->cmd == cmdTxStatus) {
                        return NanEscapeScope(argv[1]);
                    } else {
                        return NanUndefined();
                    }
                }
            } else {
                TryCatch try_catch;
                task->cb->Call(args, argv);
                if (try_catch.HasCaught()) {
                    FatalException(try_catch);
                }
                return NanUndefined();
            }
        }

        void save(BSONCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            BSONCmdData *cmdata = task->cmd_data;
            assert(cmdata);
            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }

            std::vector<bson*>::iterator it;
            for (it = cmdata->bsons.begin(); it < cmdata->bsons.end(); it++) {
                bson_oid_t oid;
                bson *bs = *(it);
                if (!bs) {
                    //Zero OID
                    oid.ints[0] = 0;
                    oid.ints[1] = 0;
                    oid.ints[2] = 0;
                } else if (!ejdbsavebson2(coll, bs, &oid, cmdata->merge)) {
                    task->cmd_ret = CMD_RET_ERROR;
                    task->cmd_ret_msg = _jb_error_msg();
                    break;
                }
                cmdata->ids.push_back(oid);
            }
        }

        Handle<Value> save_after(BSONCmdTask *task) {
            NanEscapableScope();
            Local<Value> argv[2];
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            Local<Array> oids = NanNew<Array>();
            std::vector<bson_oid_t>::iterator it;
            int32_t c = 0;
            for (it = task->cmd_data->ids.begin(); it < task->cmd_data->ids.end(); it++) {
                bson_oid_t& oid = *it;
                if (oid.ints[0] || oid.ints[1] || oid.ints[2]) {
                    char oidhex[25];
                    bson_oid_to_string(&oid, oidhex);
                    oids->Set(NanNew<Integer>(c++), NanNew<String>(oidhex));
                } else {
                    oids->Set(NanNew<Integer>(c++), NanNull());
                }
            }
            argv[1] = oids;
            if (task->cb->IsEmpty()) {
                if (task->cmd_ret != 0) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                } else 
                    return NanEscapeScope(argv[1]);
            } else {
                TryCatch try_catch;
                task->cb->Call(2, argv);
                if (try_catch.HasCaught()) {
                    FatalException(try_catch);
                }
                return NanUndefined();
            }
        }

        void load(BSONCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            BSONCmdData *cmdata = task->cmd_data;
            assert(cmdata);
            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }
            cmdata->bsons.push_back(ejdbloadbson(coll, &task->cmd_data->ref));
        }

        Handle<Value> load_after(BSONCmdTask *task) {
            NanEscapableScope();
            Local<Value> argv[2];
            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
            } else {
                argv[0] = NanNull();
            }
            bson *bs = (!task->cmd_ret && task->cmd_data->bsons.size() > 0) ?
                    task->cmd_data->bsons.front() :
                    NULL;
            if (bs) {
                bson_iterator it;
                bson_iterator_init(&it, bs);
                argv[1] = NanNew(toV8Object(&it, BSON_OBJECT));
            } else {
                argv[1] = NanNull();
            }
            if (task->cb->IsEmpty()) {
                if (task->cmd_ret != 0) {
                    NanThrowError(argv[0]); 
                    return NanUndefined();
                } else 
                    return NanEscapeScope(argv[1]);
            } else {
                TryCatch try_catch;
                task->cb->Call(2, argv);
                if (try_catch.HasCaught()) {
                    FatalException(try_catch);
                }
                return NanUndefined();
            }
        }


        void ejdbcmd(BSONQCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            BSONQCmdData *cmdata = task->cmd_data;
            std::vector<bson*> &bsons = cmdata->bsons;
            bson *qbs = bsons.front();
            assert(qbs);
            TCLIST *res = tclistnew2(1);
            bson *bret = ejdbcommand(m_jb, qbs);
            assert(bret);
            tclistpush(res, bson_data(bret), bson_size(bret));
            bson_del(bret);
            cmdata->res = res;
            cmdata->count = TCLISTNUM(cmdata->res);
            cmdata->qflags = 0;
        }

        Handle<Value> ejdbcmd_after(BSONQCmdTask *task) {
            return query_after(task);
        }


        void query(BSONQCmdTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            TCLIST *res = NULL;
            bson oqarrstack[8]; //max 8 $or bsons on stack
            BSONQCmdData *cmdata = task->cmd_data;
            std::vector<bson*> &bsons = cmdata->bsons;
            EJCOLL *coll = ejdbgetcoll(m_jb, cmdata->cname.c_str());
            if (!coll) {
                bson *qbs = bsons.front();
                bson_iterator it;
                //If we are in $upsert mode so new collection will be created
                if (qbs && bson_find(&it, qbs, "$upsert") == BSON_OBJECT) {
                    coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), NULL);
                    if (!coll) {
                        task->cmd_ret = CMD_RET_ERROR;
                        task->cmd_ret_msg = _jb_error_msg();
                        return;
                    }
                } else { //No collection -> no results
                    cmdata->res = tclistnew2(1);
                    cmdata->count = 0;
                    return;
                }
            }
            int orsz = (int) bsons.size() - 2; //Minus main qry at begining and hints object at the end
            if (orsz < 0) orsz = 0;
            bson *oqarr = ((orsz <= 8) ? oqarrstack : (bson*) malloc(orsz * sizeof (bson)));
            for (int i = 1; i < (int) bsons.size() - 1; ++i) {
                oqarr[i - 1] = *(bsons.at(i));
            }
            EJQ *q = ejdbcreatequery(
                    m_jb,
                    bsons.front(),
                    (orsz > 0 ? oqarr : NULL), orsz,
                    ((bsons.size() > 1) ? bsons.back() : NULL));
            if (!q) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                goto finish;
            }
            res = ejdbqryexecute(coll, q, &cmdata->count, cmdata->qflags, cmdata->log);
            if (ejdbecode(m_jb) != TCESUCCESS) {
                if (res) {
                    tclistdel(res);
                    res = NULL;
                }
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                goto finish;
            }
            cmdata->res = res;
finish:
            if (q) {
                ejdbquerydel(q);
            }
            if (oqarr && oqarr != oqarrstack) {
                free(oqarr);
            }
        }

        Handle<Value> query_after(BSONQCmdTask *task);

        void open(OpenCmdTask *task) {
            OpenCmdData *cmdata = task->cmd_data;
            assert(cmdata);

            if (m_jb && ejdbisopen(m_jb)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = "Database already opened";
                return;
            }
            if (!m_jb)
                m_jb = ejdbnew();
            if (!m_jb || !ejdbopen(m_jb, cmdata->path.c_str(), cmdata->mode)) {
                std::ostringstream os;
                os << "Unable to open database: " << (cmdata->path) << " error: " << _jb_error_msg();
                EJ_LOG_ERROR("%s", os.str().c_str());
                task->cmd_ret_msg = os.str();
                task->cmd_ret = CMD_RET_ERROR;
                ejdbdel(m_jb);
                m_jb = NULL;
            }
        }

        Handle<Value> open_after(OpenCmdTask *task) {
            NanEscapableScope();
            Local<Value> argv[1];
            bool sync = task->cb->IsEmpty();

            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
                if (sync) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                }
            } else {
                argv[0] = NanNull();
                if (sync)
                    return NanUndefined();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
            return NanUndefined();
        }

        void close(EJBTask *task) {
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            if (m_jb) {
                bool rv = ejdbclose(m_jb);
                ejdbdel(m_jb);
                m_jb = NULL;
                if (!rv) {
                    task->cmd_ret = CMD_RET_ERROR;
                    task->cmd_ret_msg = std::string(_jb_error_msg());
                }
                return;
            }
        }

        Handle<Value> close_after(EJBTask *task) {
            NanEscapableScope();
            Local<Value> argv[1];
            bool sync = task->cb->IsEmpty();

            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
                if (sync) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                }
            } else {
                argv[0] = NanNull();
                if (sync)
                    return NanUndefined();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
            return NanUndefined();
        }

        void ensure(EnsureCmdTask *task) {
            EnsureCmdData *cmdata = task->cmd_data;
            assert(cmdata);
            if (!_check_state((EJBTask*) task)) {
                return;
            }
            EJCOLL *coll = ejdbcreatecoll(m_jb, cmdata->cname.c_str(), &cmdata->jcopts);
            if (!coll) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = _jb_error_msg();
                return;
            }
        }

        Handle<Value> ensure_after(EnsureCmdTask *task) {
            NanEscapableScope();
            Local<Value> argv[1];
            bool sync = task->cb->IsEmpty();

            if (task->cmd_ret != 0) {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
                if (sync) {
                    NanThrowError(argv[0]);
                    return NanUndefined();
                }
            } else {
                argv[0] = NanNull();
                if (sync)
                    return NanUndefined();
            }
            TryCatch try_catch;
            task->cb->Call(1, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
            return NanUndefined();
        }

        const char* _jb_error_msg() {
            return m_jb ? ejdberrmsg(ejdbecode(m_jb)) : "Unknown error";
        }

        bool _check_state(EJBTask *task) {
            if (!ejdbisopen(m_jb)) {
                task->cmd_ret = CMD_RET_ERROR;
                task->cmd_ret_msg = "Database is not opened";
                return false;
            }
            return true;
        }

        NodeEJDB() : m_jb(NULL) {
        }

        virtual ~NodeEJDB() {
            if (m_jb) {
                ejdbdel(m_jb);
            }
        }

    public:

        static void Init(Handle<Object> target) {
            NanScope();

            //Symbols
            #define NODE_PSYMBOL(V) Eternal<String>(Isolate::GetCurrent(), NanNew<String>(V))
            
            sym_large = NODE_PSYMBOL("large");
            sym_compressed = NODE_PSYMBOL("compressed");
            sym_records = NODE_PSYMBOL("records");
            sym_cachedrecords = NODE_PSYMBOL("cachedrecords");
            sym_explain = NODE_PSYMBOL("$explain");
            sym_merge = NODE_PSYMBOL("$merge");

            sym_name = NODE_PSYMBOL("name");
            sym_iname = NODE_PSYMBOL("iname");
            sym_field = NODE_PSYMBOL("field");
            sym_indexes = NODE_PSYMBOL("indexes");
            sym_options = NODE_PSYMBOL("options");
            sym_file = NODE_PSYMBOL("file");
            sym_buckets = NODE_PSYMBOL("buckets");
            sym_type = NODE_PSYMBOL("type");

            #undef NODE_PSYMBOL


            Local<FunctionTemplate> t = NanNew<FunctionTemplate>(s_new_object);
            t->InstanceTemplate()->SetInternalFieldCount(1);
            t->SetClassName(NanNew<String>("NodeEJDB"));

            //Open mode
            NODE_DEFINE_CONSTANT(target, JBOREADER);
            NODE_DEFINE_CONSTANT(target, JBOWRITER);
            NODE_DEFINE_CONSTANT(target, JBOCREAT);
            NODE_DEFINE_CONSTANT(target, JBOTRUNC);
            NODE_DEFINE_CONSTANT(target, JBONOLCK);
            NODE_DEFINE_CONSTANT(target, JBOLCKNB);
            NODE_DEFINE_CONSTANT(target, JBOTSYNC);

            //Indexes
            NODE_DEFINE_CONSTANT(target, JBIDXDROP);
            NODE_DEFINE_CONSTANT(target, JBIDXDROPALL);
            NODE_DEFINE_CONSTANT(target, JBIDXOP);
            NODE_DEFINE_CONSTANT(target, JBIDXREBLD);
            NODE_DEFINE_CONSTANT(target, JBIDXNUM);
            NODE_DEFINE_CONSTANT(target, JBIDXSTR);
            NODE_DEFINE_CONSTANT(target, JBIDXISTR);
            NODE_DEFINE_CONSTANT(target, JBIDXARR);

            //Misc
            NODE_DEFINE_CONSTANT(target, JBQRYCOUNT);

            NODE_SET_PROTOTYPE_METHOD(t, "open", s_open);
            NODE_SET_PROTOTYPE_METHOD(t, "close", s_close);
            NODE_SET_PROTOTYPE_METHOD(t, "save", s_save);
            NODE_SET_PROTOTYPE_METHOD(t, "load", s_load);
            NODE_SET_PROTOTYPE_METHOD(t, "remove", s_remove);
            NODE_SET_PROTOTYPE_METHOD(t, "query", s_query);
            NODE_SET_PROTOTYPE_METHOD(t, "lastError", s_ecode);
            NODE_SET_PROTOTYPE_METHOD(t, "ensureCollection", s_ensure_collection);
            NODE_SET_PROTOTYPE_METHOD(t, "removeCollection", s_rm_collection);
            NODE_SET_PROTOTYPE_METHOD(t, "isOpen", s_is_open);
            NODE_SET_PROTOTYPE_METHOD(t, "setIndex", s_set_index);
            NODE_SET_PROTOTYPE_METHOD(t, "sync", s_sync);
            NODE_SET_PROTOTYPE_METHOD(t, "dbMeta", s_db_meta);
            NODE_SET_PROTOTYPE_METHOD(t, "command", s_cmd);
            NODE_SET_PROTOTYPE_METHOD(t, "_txctl", s_coll_txctl);

            //Symbols
            target->Set(NanNew<String>("NodeEJDB"), t->GetFunction());
            
            NanAssignPersistent(constructor_template, t);
        }

        void Ref() {
            ObjectWrap::Ref();
        }

        void Unref() {
            ObjectWrap::Unref();
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    //                        ResultSet cursor                               //
    ///////////////////////////////////////////////////////////////////////////

    class NodeEJDBCursor : public ObjectWrap {
        friend class NodeEJDB;

        static Persistent<FunctionTemplate> constructor_template;

        NodeEJDB *m_nejdb;
        intptr_t m_mem; //amount of memory contained in cursor

        TCLIST *m_rs; //result set bsons
        int m_pos; //current cursor position
        bool m_no_next; //no next() was called

        static NAN_METHOD(s_new_object) {
            NanEscapableScope();
            REQ_ARGS(2);
            REQ_EXT_ARG(0, nejedb);
            REQ_EXT_ARG(1, rs);
            NodeEJDBCursor *cursor = new NodeEJDBCursor((NodeEJDB*) nejedb->Value(), (TCLIST*) rs->Value());
            cursor->Wrap(args.This());
            NanReturnThis();
        }

        static NAN_METHOD(s_close) {
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap< NodeEJDBCursor > (args.This());
            c->close();
            NanReturnUndefined();
        }

        static NAN_METHOD(s_reset) { 
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap< NodeEJDBCursor > (args.This());
            c->m_pos = 0;
            c->m_no_next = true;
            NanReturnUndefined();
        }

        static NAN_METHOD(s_has_next) { 
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap< NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            int rsz = TCLISTNUM(c->m_rs);
            NanReturnValue(NanNew<Boolean>(c->m_rs && ((c->m_no_next && rsz > 0) || (c->m_pos + 1 < rsz))));
        }

        static NAN_METHOD(s_next) {
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap< NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            int rsz = TCLISTNUM(c->m_rs);
            if (c->m_no_next) {
                c->m_no_next = false;
                NanReturnValue(NanNew<Boolean>(rsz > 0));
            } else if (c->m_pos + 1 < rsz) {
                c->m_pos++;
                NanReturnValue(NanTrue());
            } else {
                NanReturnValue(NanFalse());
            }
        }

        static NAN_GETTER(s_get_length) { 
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap<NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            NanReturnValue(NanNew<Integer>(TCLISTNUM(c->m_rs)));
        }

        static NAN_GETTER(s_get_pos) {
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap<NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            NanReturnValue(NanNew<Integer>(c->m_pos));
        }

        static NAN_SETTER(s_set_pos) { 
            NanEscapableScope();
            if (!value->IsNumber()) {
                return;
            }
            NodeEJDBCursor *c = ObjectWrap::Unwrap<NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                NanReturnUndefined();
            }
            int nval = value->Int32Value();
            int rsz = TCLISTNUM(c->m_rs);
            if (nval < 0) {
                nval = rsz + nval;
            }
            if (nval >= 0 && rsz > 0) {
                nval = (nval >= rsz) ? rsz - 1 : nval;
            } else {
                nval = 0;
            }
            c->m_pos = nval;
            c->m_no_next = false;
            
            NanReturnUndefined();
        }

        static NAN_METHOD(s_field) { 
            NanEscapableScope();
            REQ_ARGS(1);
            REQ_STR_ARG(0, fpath);
            NodeEJDBCursor *c = ObjectWrap::Unwrap<NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            int pos = c->m_pos;
            int rsz = TCLISTNUM(c->m_rs);
            if (rsz == 0) {
                return NanThrowError("Empty cursor");
            }
            assert(!(pos < 0 || pos >= rsz)); //m_pos correctly set by s_set_pos
            const void *bsdata = TCLISTVALPTR(c->m_rs, pos);
            assert(bsdata);
            bson_iterator it;
            bson_iterator_from_buffer(&it, (const char*) bsdata);
            bson_type bt = bson_find_fieldpath_value2(*fpath, fpath.length(), &it);
            if (bt == BSON_EOO) {
                NanReturnUndefined();
            }
            NanReturnValue(toV8Value(&it));
        }

        static NAN_METHOD(s_object) {
            NanEscapableScope();
            NodeEJDBCursor *c = ObjectWrap::Unwrap<NodeEJDBCursor > (args.This());
            if (!c->m_rs) {
                return NanThrowError("Cursor closed");
            }
            int pos = c->m_pos;
            int rsz = TCLISTNUM(c->m_rs);
            if (rsz == 0) {
                return NanThrowError("Empty cursor");
            }
            assert(!(pos < 0 || pos >= rsz)); //m_pos correctly set by s_set_pos
            const void *bsdata = TCLISTVALPTR(c->m_rs, pos);
            assert(bsdata);
            bson_iterator it;
            bson_iterator_from_buffer(&it, (const char*) bsdata);
            
            NanReturnValue(toV8Object(&it, BSON_OBJECT));
        }

        void close() {
            if (m_nejdb) {
                m_nejdb->Unref();
                m_nejdb = NULL;
            }
            if (m_rs) {
                tclistdel(m_rs);
                m_rs = NULL;
            }
            NanAdjustExternalMemory(-m_mem + sizeof (NodeEJDBCursor));
        }

        NodeEJDBCursor(NodeEJDB *_nejedb, TCLIST *_rs) : m_nejdb(_nejedb), m_rs(_rs), m_pos(0), m_no_next(true) {
            assert(m_nejdb);
            this->m_nejdb->Ref();
            m_mem = sizeof (NodeEJDBCursor);
            if (m_rs) {
                intptr_t cmem = 0;
                int i = 0;
                for (; i < TCLISTNUM(m_rs) && i < 1000; ++i) { //Max 1K iterations
                    cmem += bson_size2(TCLISTVALPTR(m_rs, i));
                }
                if (i > 0) {
                    m_mem += (intptr_t) (((double) cmem / i) * TCLISTNUM(m_rs));
                }
                NanAdjustExternalMemory(m_mem);
            }
        }

        virtual ~NodeEJDBCursor() {
            close();
            NanAdjustExternalMemory((int)sizeof (NodeEJDBCursor) * -1);
        }

    public:

        static void Init(Handle<Object> target) {
            NanScope();

            Local<FunctionTemplate> t = NanNew<FunctionTemplate>(s_new_object);
            t->InstanceTemplate()->SetInternalFieldCount(1);
            t->SetClassName(NanNew<String>("NodeEJDBCursor"));

            t->PrototypeTemplate()->SetAccessor(NanNew<String>("length"), s_get_length, 0, Handle<Value > (), ALL_CAN_READ);
            t->PrototypeTemplate()->SetAccessor(NanNew<String>("pos"), s_get_pos, s_set_pos, Handle<Value > (), ALL_CAN_READ);

            NODE_SET_PROTOTYPE_METHOD(t, "close", s_close);
            NODE_SET_PROTOTYPE_METHOD(t, "reset", s_reset);
            NODE_SET_PROTOTYPE_METHOD(t, "hasNext", s_has_next);
            NODE_SET_PROTOTYPE_METHOD(t, "next", s_next);
            NODE_SET_PROTOTYPE_METHOD(t, "field", s_field);
            NODE_SET_PROTOTYPE_METHOD(t, "object", s_object);
            
            NanAssignPersistent(constructor_template, t);
        }

        void Ref() {
            ObjectWrap::Ref();
        }

        void Unref() {
            ObjectWrap::Unref();
        }
    };

    ///////////////////////////////////////////////////////////////////////////
    //                           rest                                        //
    ///////////////////////////////////////////////////////////////////////////

    Handle<Value> NodeEJDB::query_after(BSONQCmdTask *task) {
        NanEscapableScope();
        BSONQCmdData *cmdata = task->cmd_data;
        assert(cmdata);

        Local<Value> argv[4];
        if (task->cmd_ret != 0) { //error case
            if (task->cb->IsEmpty()) {
                NanThrowError(task->cmd_ret_msg.c_str());
                return NanUndefined();
            } else {
                argv[0] = NanError(task->cmd_ret_msg.c_str());
                TryCatch try_catch;
                task->cb->Call(1, argv);
                if (try_catch.HasCaught()) {
                    FatalException(try_catch);
                }
                return NanUndefined();
            }
        }
        TCLIST *res = cmdata->res;
        argv[0] = NanNull();
        if (res) {
            cmdata->res = NULL; //res will be freed by NodeEJDBCursor instead of ~BSONQCmdData()
            Local<Value> cursorArgv[2];
            cursorArgv[0] = NanNew<External>(task->wrapped);
            cursorArgv[1] = NanNew<External>(res);
            Local<Value> cursor(NanNew(NodeEJDBCursor::constructor_template)->GetFunction()->NewInstance(2, cursorArgv));
            argv[1] = cursor;
        } else { //this is update query so no result set
            argv[1] = NanNull();
        }
        argv[2] = NanNew<Integer>(cmdata->count);
        if (cmdata->log) {
            argv[3] = NanNew<String>((const char*) tcxstrptr(cmdata->log));
        }
        
        if (task->cb->IsEmpty()) {
            if (res) {
                return NanEscapeScope(argv[1]); //cursor
            } else {
                return NanEscapeScope(argv[2]); //count
            }
        } else {
            TryCatch try_catch;
            task->cb->Call((cmdata->log) ? 4 : 3, argv);
            if (try_catch.HasCaught()) {
                FatalException(try_catch);
            }
            return NanUndefined();
        }
    }

    void Init(Handle<Object> target) {
#ifdef __unix
        setlocale(LC_ALL, "en_US.UTF-8"); //todo review it
#endif
        ejdb::NodeEJDB::Init(target);
        ejdb::NodeEJDBCursor::Init(target);
}

Persistent<FunctionTemplate> NodeEJDB::constructor_template;
Persistent<FunctionTemplate> NodeEJDBCursor::constructor_template;

}

// Register the module with node.
NODE_MODULE(ejdb_native, ejdb::Init)
