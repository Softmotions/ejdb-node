#!/usr/bin/env node

var cdb = null; //current DB desc
const maxInspectRows = 10;
const maxInspectDepth = 10;
var useColors = true;
var quiet = false;
var cmd = null;
var pkg = require("../package.json");


//Parse aguments
(function () {
    var args = process.argv;
    for (var i = 2; i < args.length; ++i) {
        var a = args[i];
        if (["--help", "-h"].indexOf(a) !== -1) {
            help();
        } else if (["--no-colors", "-n"].indexOf(a) !== -1) {
            useColors = false;
        } else if (["--quiet", "-q"].indexOf(a) !== -1) {
            quiet = true;
        } else if (["--cmd", "-c"].indexOf(a) !== -1) {
            cmd = a;
        } else if (i === args.length - 1) { //last arg
            cmd = "db.open('" + a + "')";  //todo review
        }
    }
})();

function help() {
    var h = [];
    h.push("EJDB CLI v" + pkg.version);
    h.push("usage: ejdb [options] [dbfile]");
    h.push("options:");
    h.push("\t-h --help\tshow this help tip");
    h.push("\t-n --no-colors\tdo not use colored output");
    h.push("\t-q --quiet\trun in quiet output mode");
    h.push("\t-c --cmd\trun specified javascript command");
    console.error(h.join("\n"));
    process.exit(0);
}

if (!quiet) {
    console.log("Welcome to EJDB CLI v" + pkg.version);
}

var util = require("util");
var path = require("path");
var EJDB = require("../ejdb.js");
var clinspect = require("../clinspect.js");

// help messages (for methods with collection)
var helpGetters = {
    save : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "object|array of object, [opts], [cb]) Save/update specified JSON objects in the collection."
    },
    load : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "oid, [cb]) Loads object identified by OID from the collection"
    },
    remove : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "oid, [cb]) Removes object from the collection"
    },
    find : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "[qobj], [qobjarr], [hints], [cb]) Execute query on collection"
    },
    findOne : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "[qobj], [qobjarr], [hints], [cb]) Retrive one object from the collection"
    },
    update : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "[qobj], [qobjarr], [hints], [cb]) Perform update query on collection"
    },
    count : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "[qobj], [qobjarr], [hints], [cb]) Convenient count(*) operation"
    },
    dropIndexes : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Drop indexes of all types for JSON field path"
    },
    optimizeIndexes : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Optimize indexes of all types for JSON field path"
    },

    ensureStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Ensure String index for JSON field path"
    },
    rebuildStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },
    dropStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },

    ensureIStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Ensure case insensitive String index for JSON field path"
    },
    rebuildIStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },
    dropIStringIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },

    ensureNumberIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Ensure index presence of Number type for JSON field path"
    },
    rebuildNumberIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },
    dropNumberIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },

    ensureArrayIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb]) Ensure index presence of Array type for JSON field path"
    },
    rebuildArrayIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    },
    dropArrayIndex : function (selected) {
        return "(" + (!selected ? "cname, " : "") + "path, [cb])"
    }
};

//Init help hints
Object.defineProperty(EJDB.open, "_help_", {value : "(dbFile, [openMode], [cb]) Open database"});
Object.defineProperty(EJDB.prototype.close, "_help_", {value : "([cb]) Close database"});
Object.defineProperty(EJDB.prototype.isOpen, "_help_", {value : "Check if database in opened state"});
Object.defineProperty(EJDB.prototype.ensureCollection, "_help_", {value : "(cname, [copts], [cb]) Creates new collection if it does't exists"});
Object.defineProperty(EJDB.prototype.dropCollection, "_help_", {value : "(cname, [prune], [cb]) Drop collection, " +
                                                                        "if `prune` is true collection db files will be erased from disk."});

Object.defineProperty(EJDB.prototype.getDBMeta, "_help_", {value : "Get description of EJDB database and its collections"});
Object.defineProperty(EJDB.prototype.sync, "_help_", {value : "Synchronize entire EJDB database with disk"});

Object.defineProperty(EJDB.prototype.save, "_help_", {value : helpGetters.save()});
Object.defineProperty(EJDB.prototype.load, "_help_", {value : helpGetters.load()});
Object.defineProperty(EJDB.prototype.remove, "_help_", {value : helpGetters.remove()});
Object.defineProperty(EJDB.prototype.find, "_help_", {value : helpGetters.find()});
Object.defineProperty(EJDB.prototype.findOne, "_help_", {value : helpGetters.findOne()});
Object.defineProperty(EJDB.prototype.update, "_help_", {value : helpGetters.update()});
Object.defineProperty(EJDB.prototype.count, "_help_", {value : helpGetters.count()});
Object.defineProperty(EJDB.prototype.dropIndexes, "_help_", {value : helpGetters.dropIndexes()});
Object.defineProperty(EJDB.prototype.optimizeIndexes, "_help_", {value : helpGetters.optimizeIndexes()});

Object.defineProperty(EJDB.prototype.ensureStringIndex, "_help_", {value : helpGetters.ensureStringIndex()});
Object.defineProperty(EJDB.prototype.rebuildStringIndex, "_help_", {value : helpGetters.rebuildStringIndex()});
Object.defineProperty(EJDB.prototype.dropStringIndex, "_help_", {value : helpGetters.dropStringIndex()});

Object.defineProperty(EJDB.prototype.ensureIStringIndex, "_help_", {value : helpGetters.ensureIStringIndex()});
Object.defineProperty(EJDB.prototype.rebuildIStringIndex, "_help_", {value : helpGetters.rebuildIStringIndex()});
Object.defineProperty(EJDB.prototype.dropIStringIndex, "_help_", {value : helpGetters.dropIStringIndex()});

Object.defineProperty(EJDB.prototype.ensureNumberIndex, "_help_", {value : helpGetters.ensureNumberIndex()});
Object.defineProperty(EJDB.prototype.rebuildNumberIndex, "_help_", {value : helpGetters.rebuildNumberIndex()});
Object.defineProperty(EJDB.prototype.dropNumberIndex, "_help_", {value : helpGetters.dropNumberIndex()});

Object.defineProperty(EJDB.prototype.ensureArrayIndex, "_help_", {value : helpGetters.ensureArrayIndex()});
Object.defineProperty(EJDB.prototype.rebuildArrayIndex, "_help_", {value : helpGetters.rebuildArrayIndex()});
Object.defineProperty(EJDB.prototype.dropArrayIndex, "_help_", {value : helpGetters.dropArrayIndex()});

Object.defineProperty(EJDB.prototype.beginTransaction, "_help_", {value : "Begin collection transaction"});
Object.defineProperty(EJDB.prototype.commitTransaction, "_help_", {value : "Commit collection transaction"});
Object.defineProperty(EJDB.prototype.rollbackTransaction, "_help_", {value : "Rollback collection transaction"});
Object.defineProperty(EJDB.prototype.getTransactionStatus, "_help_", {value : "Get collection transaction status"});

// collection controllers history (for merge)
var cchistory = [];

// bind collections controllers
// dbctrl - db controller
// forcerebind - if <code>true</code> force rebind all collection controllers, otherwise check added/deleted collections
var bindColCtls = function(dbctrl, forcerebind) {
    var octrls = forcerebind ? [] : cchistory;
    var nctrls = [];

    var dbMeta = cdb.jb.getDBMeta();
    if (dbMeta && dbMeta.collections) {
        for (var j = 0; j < dbMeta.collections.length; ++j) {
            var collection = dbMeta.collections[j];
            var ci;
            if ((ci = octrls.indexOf(collection.name)) != -1) {
                nctrls.push(collection.name);
                octrls.splice(ci, 1);
            } else if (!dbctrl[collection.name]){
                nctrls.push(collection.name);
                dbctrl[collection.name] = colctl(dbctrl, collection.name);
            }
        }
    }
    for (var i = 0; i < octrls.length; ++i) {
        delete dbctrl[octrls[i]];
    }

    // save current known collections
    cchistory = nctrls;
};

// collection controller (creation function)
var colctl = function (db, cname) {
    // build arguments function: add <cname> as first argument
    var buildargs = function (args) {
        var result = [cname];
        // args is Object, we need to iterate all fields with numeric key for collecting arguments
        for (var i = 0; args[i]; ++i) {
            result.push(args[i]);
        }

        return result;
    };
    // method names for creating aliases (db.<method>(cname, ...) -> db.cname.<method>(...))
    var mnames = [
        "save", "load", "remove", "find", "findOne", "update", "count",
        "dropCollection", "dropIndexes", "optimizeIndexes",
        "ensureStringIndex", "rebuildStringIndex", "dropStringIndex",
        "ensureIStringIndex", "rebuildIStringIndex", "dropIStringIndex",
        "ensureNumberIndex", "rebuildNumberIndex", "dropNumberIndex",
        "ensureArrayIndex", "rebuildArrayIndex", "dropArrayIndex"
    ];
    // bind method alias
    var mbind = function (mname) {
        return function () {
            return db[mname].apply(db, buildargs(arguments));
        }
    };

    // collection controller impl
    var colctlimpl = {
    };

    var mname;
    // wrap methods
    for (var i = 0; i < mnames.length; ++i) {
        mname = mnames[i];
        colctlimpl[mname] = mbind(mname);
        if (helpGetters[mname]) {
            Object.defineProperty(colctlimpl[mname], '_help_', {value : helpGetters[mname](true)});
        }
    }

    return colctlimpl
};

repl = require("repl").start({
    prompt : "ejdb> ",
    input : process.stdin,
    output : process.stdout,
    terminal : true,
    writer : function (obj) {
        return clinspect.inspect(obj, maxInspectDepth, useColors)
    }
});

//console.log("MF=" +  module.filename);

var dbctl = {
    open : function (dbpath) {
        if (dbpath == null) {
            return error("No file path specified");
        }
        if (cdb) {
            return error("Database already opened: " + cdb.dbpath);
        }
        dbpath = path.resolve(dbpath);
        cdb = {
            dbpath : dbpath,
            jb : EJDB.open(dbpath)
        };
        syncdbctx();
        return dbstatus(cdb);
    },

    status : function () {
        syncdbctx();
        return dbstatus(cdb);
    },

    close : function () {
        if (!cdb || !cdb.jb) {
            return error("Database already closed");
        }
        try {
            cdb.jb.close();
        } finally {
            cdb = null;
        }
        syncdbctx();
    }
};
Object.defineProperty(dbctl.open, "_help_", {value : EJDB.open._help_});
Object.defineProperty(dbctl.close, "_help_", {value : EJDB.prototype.close._help_});
Object.defineProperty(dbctl.status, "_help_", {value : "Get current database status"});

repl.on("exit", function () {
    dbctl.close();
    console.log("Bye!");
});

function dbstatus(cdb) {
    if (cdb) {
        return cdb.jb.getDBMeta();
    } else {
        return {};
    }
}

function syncdbctx() {
    var db = {};
    repl.resetContext();
    if (cdb && cdb.jb) {
        db.__proto__ = cdb.jb;
        db.close = dbctl.close;
        db.status = dbctl.status;
        db.find = function () {
            var ret = cdb.jb.find.apply(cdb.jb, arguments);
            if (typeof ret === "object") {
                if (!quiet) {
                    println("Found " + ret.length + " records");
                }
                for (var i = 0; ret.next() && i < maxInspectRows; ++i) {
                    println(repl.writer(ret.object()));
                }
                ret.reset();
                if (ret.length > maxInspectRows) {
                    if (!quiet) {
                        println("Shown only first " + maxInspectRows);
                    }
                }
                if (!quiet) {
                    println("\nReturned cursor:");
                }
            }
            // rebind collection controlles if need
            if (!db[arguments[0]]) {
                bindColCtls(db);
            }
            return ret;
        };
        Object.defineProperty(db.find, "_help_", {value : EJDB.prototype.find._help_});

        // db - db controller
        // mname - method name
        // frc - force rebind collections controllers. if <code>false</code> db meta will be reloaded only if method executes on unknown collection.
        // argl - arguments count (for register callback as last argument)
        var dbbind = function(db, mname, frc) {
            return function() {
                var cname = arguments[0];
                var args = [cname];
                // copy all arguments except first and last
                for(var i = 1; i < arguments.length - 1; ++i) {
                    args.push(arguments[i]);
                }

                // creating callback with collection rebuilding
                var ccb = function(rcb) {
                    return function() {
                        if (frc || !db[cname]) {
                            bindColCtls(db);
                        }
                        if (rcb) {
                            rcb.apply(this, arguments);
                        }
                    }
                };

                if (arguments.length > 1) {
                    if (typeof arguments[arguments.length - 1] === 'function') {
                        // wrap existing callback
                        args.push(ccb(arguments[arguments.length - 1]));
                    } else {
                        // adding registering callback after last argument
                        args.push(arguments[arguments.length - 1]);
                        args.push(ccb());
                    }
                } else {
                    args.push(ccb());
                }

                return cdb.jb[mname].apply(cdb.jb, args);
            }
        };

        var rbmnames, j;
        // reload collections statuses for some methods (rebind collection controllers if need, force)
        rbmnames = ["ensureCollection", "dropCollection"];
        for (j = 0; j < rbmnames.length; ++j) {
            db[rbmnames[j]] = dbbind(db, rbmnames[j], true);
            Object.defineProperty(db[rbmnames[j]], "_help_", {value : EJDB.prototype[rbmnames[j]]._help_});
        }

        // reload collections statuses for some methods (rebind collection controllers if need, non force)
        rbmnames = ["save", "update"];
        for (j = 0; j < rbmnames.length; ++j) {
            db[rbmnames[j]] = dbbind(db, rbmnames[j]);
            Object.defineProperty(db[rbmnames[j]], "_help_", {value : EJDB.prototype[rbmnames[j]]._help_});
        }

        // bind collection controllers for all known collections
        bindColCtls(db, true);
    } else {
        db.__proto__ = dbctl;
    }
    repl.context.db = db;
    repl.context.EJDB = EJDB;
}

function println(msg) {
    repl.outputStream.write(msg + "\n");
}

function error(msg) {
    return "ERROR: " + msg;
}

syncdbctx();


if (cmd) {
    repl.rli.write(cmd + "\n");
}
