# mod_mongo #

mod_mongo is mongoDB handler module for Apache HTTPD Server.

## Dependencies ##

* [mongoDB driver](http://dl.mongodb.org/dl/cxx-driver)
* [V8](http://code.google.com/p/v8)
* [libapreq2](http://httpd.apache.org/apreq)

## Build ##

    % ./autogen.sh (or autoreconf -i)
    % ./configure [OPTION]
    % make
    % make install

### Build Options ###

mongoDB path.

* --with-mongo=PATH  [default=/usr/include]
* --with-mongo-lib=PATH  [default=no]

V8 path.

* --with-v8=PATH  [default=/usr/include]
* --with-v8-lib=PATH  [default=no]

V8 isolate.

* --enable-v8-isolate  [default=no]

apache path.

* --with-apxs=PATH  [default=yes]
* --with-apr=PATH  [default=yes]
* --with-apreq2=PATH  [default=yes]

## Configration ##

httpd.conf:

    LoadModule v8_module modules/mod_v8.so
    <IfModule mongo_module>
        MongoHost    localhost
        MongoPort    27017
        MongoTimeout 5
    </IfModule>
    AddHandler mongo-script .mongo

## Example ##

test.mongo:

    //namespace (#db#.#collection#)
    var ns = 'db.collection';

    //insert
    ret = mongo.insert(ns, { test: 'test' });

    mongo.ap.rputs(ret + "\n");
    mongo.ap.rputs(mongo.toJson(ret) + "\n"); //json string

    //find
    ret = mongo.find(ns, {});
    for (i = 0; i < ret.length; i++) {
        mongo.ap.rputs(mongo.toJson(ret[i]) + "\n");
    }

    //findOne
    ret = mongo.findOne(ns, {});
    mongo.ap.rputs(mongo.toJson(ret) + "\n");

    //update
    ret = mongo.update(ns, { test: 'test' }, { test: 'TEST', hoge: 'HOGE' });

    //remove
    ret = mongo.remove(ns, {});

    //findAndModify
    ret = mongo.findAndModify(ns, { inprogress: false }, { priority: -1 },
                              false, { $set: { inprogress: true }, true);
