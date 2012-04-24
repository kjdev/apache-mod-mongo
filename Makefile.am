
ACLOCAL_AMFLAGS = -I m4

moddir = @APACHE_MODULEDIR@
mod_LTLIBRARIES = mod_mongo.la

mod_mongo_la_SOURCES = mod_mongo.cpp
mod_mongo_la_CFLAGS = @APACHE_CFLAGS@ @APACHE_INCLUDES@ @MONGO_INCLUDES@
mod_mongo_la_CPPFLAGS = @APACHE_CPPFLAGS@ @APACHE_INCLUDES@ @MONGO_INCLUDES@
mod_mongo_la_LDFLAGS = -avoid-version -module @APACHE_LDFLAGS@
mod_mongo_la_LIBS = @APACHE_LIBS@ @MONGO_LIBS@
