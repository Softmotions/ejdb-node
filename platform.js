var cmd = process.argv[2];
var exec = require("child_process").exec;
var spawn = require("child_process").spawn;
var fs = require("fs");
var path = require("path");
var https = require("https");
var util = require("util");
var os = require("os");

var make = process.env.MAKE || "make";

if (process.platform === "win32") {
    win();
} else {
    nix();
}

function exithandler(cmd, cb) {
    return function(code) {
        if (code != null && code !== 0) {
            console.log("" + cmd + " process exited with code " + code);
            process.exit(code);
        }
        if (cb) {
            cb();
        }
    }
}

function nix() {

    switch (cmd) {

        case "preinstall":
        {
            var config = {};
            fs.writeFileSync("configure.gypi", JSON.stringify(config));

            console.log("Building EJDB...");
            var m = spawn(make, ["-f", "libejdb.mk"], {"stdio" : "inherit"});
            m.on("close", exithandler(make + " all", function() {
                var ng = spawn("node-gyp", ["rebuild"], {stdio : "inherit"});
                ng.on("close", exithandler("node-gyp"));
            }));
            break;
        }
        case "test":
        {
            console.log("Tesing Node EJDB...");
            var m = spawn(make, ["-f", "tests.mk", "check"], {stdio : "inherit"});
            m.on("close", exithandler(make));
        }
    }
}


function win() {

    switch (cmd) {

        case "preinstall":
        {
            var dlurl = process.env["npm_package_config_windownloadurl_" + os.arch()];
            if (dlurl == null) {
                console.log("Invalid package configuration, missing windows binaries download url");
                process.exit(1);
            }
            var sdir = "ejdbdll";
            try {
                fs.statSync(sdir);
            } catch (e) {
                if ("ENOENT" !== e.code) {
                    throw e;
                }
                fs.mkdirSync(sdir);
            }

            var zfileExist = false;
            var zfile = path.join(sdir, path.basename(dlurl));
            try {
                fs.statSync(zfile);
                zfileExist = true;
            } catch (e) {
                if ("ENOENT" !== e.code) {
                    throw e;
                }
            }

            if (!zfileExist) {
                console.log("Downloading windows binaries from: %s ...", dlurl);
                console.log("File: %s", zfile);
                var req = https.get(dlurl, function(res) {
                    if (res.statusCode !== 200) {
                        console.log("Invalid response code %d", res.statusCode);
                        process.exit(1);
                    }
                    var len = 0;
                    var cnt = 0;
                    var wf = fs.createWriteStream(zfile);
                    var eh = function(ev) {
                        console.log("Error receiving data from %s Error: %s", dlurl, ev);
                        process.exit(1);
                    };
                    wf.on("error", eh);
                    res.on("error", eh);
                    res.on("data", function(chunk) {
                        if (++cnt % 80 == 0) {
                            process.stdout.write("\n");
                        }
                        len += chunk.length;
                        process.stdout.write(".");
                    });
                    res.on("end", function() {
                        console.log("\n%d bytes received", len);
                        setTimeout(processArchive, 2000);
                    });
                    res.pipe(wf);
                });
                req.end();
            } else {
                processArchive();
            }

            function processArchive() {
                var targz = require("tar.gz");
                console.log("Unzip archive '%s'", zfile);
                var tgz = new targz();
                tgz.extract(zfile, sdir, function(err){
                    if (err) {
                        console.log(err);
                        process.exit(1);
                        return;
                    }

                    sdir = path.resolve(sdir);

                    var config = {};
                    config["variables"] = {
                        "EJDB_HOME" : sdir
                    };
                    fs.writeFileSync("configure.gypi", JSON.stringify(config));

                    var args = ["configure", "rebuild"];
                    console.log("node-gyp %j", args);
                    var ng = spawn("node-gyp.cmd", args, {stdio : "inherit"});
                    ng.on("error", function(ev) {
                        console.log("Spawn error: " + ev);
                        process.exit(1);
                    });
                    ng.on("close", exithandler("node-gyp", function() {
                        copyFile(path.join(sdir, "bin/libejdb.dll"),
                                "build/Release/libejdb.dll",
                                exithandler("copy libejdb.dll"));
                    }));
                });
            }
        }
    }
}


function copyFile(source, target, cb) {
    var cbCalled = false;
    var rd = fs.createReadStream(source);
    rd.on("error", function(err) {
        done(err);
    });
    var wr = fs.createWriteStream(target);
    wr.on("error", function(err) {
        done(err);
    });
    wr.on("close", function(ex) {
        done();
    });
    rd.pipe(wr);
    function done(err) {
        if (!cbCalled) {
            cb(err);
            cbCalled = true;
        }
    }
}
