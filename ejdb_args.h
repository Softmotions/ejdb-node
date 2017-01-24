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

#ifndef EJDB_ARGS_H
#define	EJDB_ARGS_H

#include <v8.h>
#include <node.h>


#define REQ_ARGS(N)                                                                       \
  if (info.Length() < (N))                                                                \
    return Nan::ThrowError("Expected " #N " arguments");

#define REQ_STR_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsString())                                       \
    return Nan::ThrowTypeError("Argument " #I " must be a string");     \
  String::Utf8Value VAR(info[I]->ToString());

#define REQ_STRW_ARG(I, VAR)                                                              \
  if (info.Length() <= (I) || !info[I]->IsString())                                       \
    return Nan::ThrowTypeError("Argument " #I " must be a string");     \
  String::Value VAR(info[I]->ToString());


#define REQ_FUN_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsFunction())                                     \
    return Nan::ThrowTypeError("Argument " #I " must be a function");   \
  Local<Function> VAR = Local<Function>::Cast(info[I]);

#define REQ_OBJ_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsObject())                                       \
    return Nan::ThrowTypeError("Argument " #I " must be a object");     \
  Local<Object> VAR = Local<Object>::Cast(info[I]);

#define REQ_VAL_ARG(I, VAR)                                                               \
  if (info.Length() <= (I))												                  \
    return Nan::ThrowTypeError("Argument " #I " must be a provided");   \
  Local<Value> VAR = info[I];


#define REQ_ARR_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsArray())                                        \
    return Nan::ThrowTypeError("Argument " #I " must be an array");     \
  Local<Array> VAR = Local<Array>::Cast(info[I]);


#define REQ_EXT_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsExternal())                                     \
    return Nan::ThrowTypeError("Argument " #I " invalid");              \
  Local<External> VAR = Local<External>::Cast(info[I]);

#define OPT_INT_ARG(I, VAR, DEFAULT)                                                      \
  int VAR;                                                                                \
  if (info.Length() <= (I)) {                                                             \
    VAR = (DEFAULT);                                                                      \
  } else if (info[I]->IsInt32()) {                                                        \
    VAR = info[I]->Int32Value();                                                          \
  } else {                                                                                \
    return Nan::ThrowTypeError("Argument " #I " must be an integer");       \
  }

#define REQ_INT32_ARG(I, VAR)                                                             \
  if (info.Length() <= (I) || !info[I]->IsInt32())                                        \
    return Nan::ThrowTypeError("Argument " #I " must be an integer");      \
  int32_t VAR = info[I]->Int32Value();


#define REQ_INT64_ARG(I, VAR)                                                             \
  if (info.Length() <= (I) || !info[I]->IsNumber())                                       \
    return Nan::ThrowTypeError("Argument " #I " must be an number");       \
  int64_t VAR = info[I]->IntegerValue();



#define REQ_NUM_ARG(I, VAR)                                                               \
  if (info.Length() <= (I) || !info[I]->IsNumber())                                       \
    return Nan::ThrowTypeError("Argument " #I " must be an number");       \
  double VAR = info[I]->ToNumber()->Value();


#define REQ_BUFF_ARG(I, VAR)                                                              \
  if (!Buffer::HasInstance(info[I])) {                                                    \
     return Nan::ThrowTypeError("Argument " #I " must to be a buffer");    \
  }                                                                                       \
  Buffer* VAR = ObjectWrap::Unwrap<Buffer>(info[I]->ToObject());


#endif	/* EJDB_ARGS_H */

