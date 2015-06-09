EJDB NodeJS binding http://ejdb.org
===================================

[![Join the chat at https://gitter.im/Softmotions/ejdb](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Softmotions/ejdb?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Installation
-----------------------------------
[http://ejdb.org/doc/bindings/nodejs/index.html](http://ejdb.org/doc/bindings/nodejs/index.html)

API
-----------------------------------
[http://ejdb.org/doc/bindings/nodejs/api.html](http://ejdb.org/doc/bindings/nodejs/api.html)

One snippet intro
-----------------------------------

```js
var EJDB = require("ejdb");
//Open zoo DB
var jb = EJDB.open("zoo",
                    EJDB.DEFAULT_OPEN_MODE | EJDB.JBOTRUNC);

var parrot1 = {
    "name" : "Grenny",
    "type" : "African Grey",
    "male" : true,
    "age" : 1,
    "birthdate" : new Date(),
    "likes" : ["green color", "night", "toys"],
    "extra1" : null
};
var parrot2 = {
    "name" : "Bounty",
    "type" : "Cockatoo",
    "male" : false,
    "age" : 15,
    "birthdate" : new Date(),
    "likes" : ["sugar cane"]
};

jb.save("parrots", [parrot1, parrot2], function(err, oids) {
    if (err) {
        console.error(err);
        return;
    }
    console.log("Grenny OID: " + parrot1["_id"]);
    console.log("Bounty OID: " + parrot2["_id"]);

    jb.find("parrots",
            {"likes" : "toys"},
            {"$orderby" : {"name" : 1}},
            function(err, cursor, count) {
                if (err) {
                    console.error(err);
                    return;
                }
                console.log("Found " + count + " parrots");
                while (cursor.next()) {
                    console.log(cursor.field("name") + " likes toys!");
                }
                //It's not mandatory to close cursor explicitly
                cursor.close();
                jb.close(); //Close the database
            });
});

```

