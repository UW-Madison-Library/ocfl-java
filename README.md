# OCFL Java

This project is a Java implementation of the [OCFL
spec](https://ocfl.io).

![build](https://github.com/UW-Madison-Library/ocfl-java/workflows/Build/badge.svg)

## Requirements and Setup

`ocfl-java` is a Java 11 project and at the minimum requires Java 11
to run.

Add the following to your project's POM to pull in the library:

```xml
<dependency>
    <groupId>edu.wisc.library.ocfl</groupId>
    <artifactId>ocfl-java-core</artifactId>
    <version>1.0.2</version>
</dependency>
```

Add the following if you'd like to use Amazon S3 for the storage
layer:

```xml
<dependency>
    <groupId>edu.wisc.library.ocfl</groupId>
    <artifactId>ocfl-java-aws</artifactId>
    <version>1.0.2</version>
</dependency>
```

## Example Usage

```java
var repoDir = Paths.get("ocfl-repo"); // This directory contains the OCFL storage root.
var workDir = Paths.get("ocfl-work"); // This directory is used to assemble OCFL versions. It cannot be within the OCFL storage root.

var repo = new OcflRepositoryBuilder()
        .defaultLayoutConfig(new HashedNTupleLayoutConfig())
        .fileSystemStorage(storage -> storage.repositoryRoot(repoDir))
        .workDir(workDir)
        .build();

repo.putObject(ObjectVersionId.head("o1"), Paths.get("object-out-dir"), new VersionInfo().setMessage("initial commit"));
repo.getObject(ObjectVersionId.head("o1"), Paths.get("object-in-dir"));

repo.updateObject(ObjectVersionId.head("o1"), new VersionInfo().setMessage("update"), updater -> {
    updater.addPath(Paths.get("path-to-file2"), "file2")
            .removeFile("file1")
            .addPath(Paths.get("path-to-file3"), "dir1/file3");
});

// Contains object details and lazy-load resource handles
var objectVersion = repo.getObject(ObjectVersionId.version("o1", "v1"));
```

## OCFL Repository Configuration

Use the `OcflRepositoryBuilder` to construct `OcflRepository`
instances. You should only create a single `OcflRepository` instance
per OCFL repository, and you should not reuse the same
`OcflRepositoryBuilder` to create multiple `OcflRepository` instances.

The `OcflRepositoryBuilder` will initialize a new OCFL repository if
it's pointed at an empty directory, or open an existing repository if
it's pointed at an existing OCFL storage root.

Use `OcflRepositoryBuilder.build()` to construct standard OCFL
repository and `OcflRepositoryBuilder.buildMutable()` to construct an
OCFL repository that supports the [mutable HEAD extension](https://ocfl.github.io/extensions/0005-mutable-head.html).

### Required Properties

* **storage**: Sets the storage layer implementation that the OCFL
repository should use. Use `FileSystemOcflStorage.builder()` or
`CloudOcflStorage.builder()` to create the `OcflStorage`
implementation.
* **workDir**: Sets the path to the directory that is used to assemble
OCFL versions. If you are using filesystem storage, it is critical
that this directory is located on the same volume as the OCFL storage
root.
* **defaultLayoutConfig**: Configures the default storage layout the
OCFL repository uses. The storage layout is used to map OCFL object
IDs to object root directories within the repository. The layout
configuration must be set when creating new OCFL repositories, but is
not required when opening an existing repository. Storage layouts must
be defined in by an [OCFL
extension](https://github.com/OCFL/extensions). Currently, the
following extensions are implemented:
  * [0002-flat-direct-storage-layout](https://ocfl.github.io/extensions/0002-flat-direct-storage-layout.html): `FlatLayoutConfig`
  * [0003-hash-and-id-n-tuple-storage-layout](https://ocfl.github.io/extensions/0003-hash-and-id-n-tuple-storage-layout.html): `HashedNTupleIdEncapsulationLayoutConfig`
  * [0004-hashed-n-tuple-storage-layout](https://ocfl.github.io/extensions/0004-hashed-n-tuple-storage-layout.html): `HashedNTupleLayoutConfig`
 
### Optional Properties

* **ocflConfig**: Sets the following default values that are used for
creating new OCFL objects: version, digest algorithm, and content
directory. The defaults are `v1`, `sha512`, and `content`.
* **prettyPrintJson**: Enables pretty print JSON in newly written
 inventory files. By default, pretty printing is disabled to reduce
 inventory file size.
* **contentPathConstraints**: Configures what file name constraints
are enforced on OCFL content paths. By default, there are no special
constraints applied. Used `ContentPathConstraints` for a selection of
pre-configured defaults. You may want to apply constraints if you are
concerned about portability between filesystems. For example,
disallowing `:` and `\` characters.
* **logicalPathMapper**: `LogicalPathMapper` implementations are used
 to map logical paths to safe content paths. By default, logical paths
 are mapped directly to content paths without making any changes. See
 `LogicalPathMappers` for more pre-configured options, such as
 `LogicalPathMappers.percentEncodingWindowsMapper()`, which
 percent-encodes a handful of characters that are problematic on
 Windows.
* **unsupportedExtensionBehavior**: By default set to `FAIL`, which
  means that repositories and objects that contain unsupported
  extensions will not be allowed. May be set to `WARN` to all
  unsupported extensions.
* **ignoreUnsupportedExtensions**: A set of unsupported extension
  names that should be allowed either without causing a failure, if
  `unsupportedExtensionBehavior` is set to `FAIL`, or not logging, if
  set to `WARN`
* **inventoryCache**: By default, an in-memory
[Caffeine](https://github.com/ben-manes/caffeine) cache is used to
cache deserialized inventories.
* **objectLock**: Set the lock implementation that's used to lock
objects for writing. By default, it is an in-memory lock with a 10
second wait to acquire. Use `ObjectLockBuilder` construct an alternate
lock. When more than one processes may be concurrently writing to an
OCFL repository or when using cloud storage, a different
implementation, such as `PostgresObjectLock`, should be used.
* **objectDetailsDb**: Configures a database to use to store OCFL
object metadata. By default, this feature is not used. It should be
used when using cloud storage. Use `ObjectDetailsDatabaseBuilder` to
construct an `ObjectDetailsDatabase`.

## Storage Implementations

### Filesystem

The basic OCFL repository implementation stores objects under an OCFL
storage root on a locally attached filesystem. The client constructs
new object versions in a work directory before attempting to move them
into the object root. Ideally, this move operation can be executed as
an atomic rename, and, as such, the work directory configured on the
`ocfl-java` client should be located on the same mount as the OCFL
storage root.

### Configuration

Use `FileSystemOcflStorage.builder()` to create and configure an
`OcflStorage` instance.

* **repositoryRoot**: Required, path to the OCFL storage root
  directory.
* **checkNewVersionFixity**: Optional, instructs the client to check
the fixity of every file in new versions once the version is at rest.
By default, this is disabled and it is unlikely to be worthwhile if
the work directory and OCFL storage root are on the same mount, as
recommended.

**Example**

```java
var repo = new OcflRepositoryBuilder()
        .defaultLayoutConfig(new HashedTruncatedNTupleConfig())
        .fileSystemStorage(storage -> storage.repositoryRoot(repoDir))
        .workDir(workDir)
        .build();
```

### Amazon S3

The Amazon S3 storage implementation stores OCFL objects directly in
an Amazon S3 bucket. Optionally, a key prefix can be used to partition
the repository to use only a portion of its bucket, allowing you to
store multiple OCFL repositories in the same bucket or non-OCFL
content.

At the minimum, the client needs permissions to the following actions:

* `s3:PutObject`
* `s3:GetObject`
* `s3:DeleteObject`
* `s3:ListBucket`
* `s3:AbortMultipartUpload`

The `ocfl-client` needs to be configured to use a database for locking
and caching OCFL object details. This is necessary to solve eventual
consistency and concurrency issues. Use
`OcflRepositoryBuilder.objectLock()` and
`OcflRepositoryBuilder.objectDetailsDb()` to set this up. Currently,
the only supported databases are PostgreSQL and H2. The `ocfl-java`
client populates the object details database on demand. There is no
need to pre-populate it, and it can safely be wiped anytime.

Note, the Amazon S3 storage implementation is significantly slower
than the file system implementation. It will likely not perform well
on large files or objects with lots of files. Additionally, it does
not cache any object files locally, requiring them to be retrieved
from S3 on every access.

### Configuration

Use `CloudOcflStorage.builder()` to create and configure an
`OcflStorage` instance.

* **cloudClient**: Required, sets the `CloudClient` implementation to
  use. For Amazon S3, use `OcflS3Client.builder()`.

**Example**

```java
var repo = new OcflRepositoryBuilder()
        .defaultLayoutConfig(new HashedNTupleLayoutConfig())
        .contentPathConstraints(ContentPathConstraints.cloud())
        .objectLock(lock -> lock.dataSource(dataSource))
        .objectDetailsDb(db -> db.dataSource(dataSource))
        .cloudStorage(storage -> storage
                .cloudClient(OcflS3Client.builder()
                        .s3Client(s3Client)
                        .bucket(name)
                        .repoPrefix(prefix)
                        .build()))
        .workDir(workDir)
        .build();
```

## Database

If you use a database backed object lock or the object details
database, then you'll need to setup a database for the client to
connect to. Currently, only PostgreSQL >= 9.3 and H2 are supported.
The client automatically creates the tables that it needs.

## Usage Considerations

### Running multiple instances

If you intend to write to an OCFL repository from multiple different
instances, you should use a database based object lock rather than the
default in-memory lock. This is a requirement for using cloud storage,
by not strictly necessary for filesystem storage. Additionally, you
may want to either adjust or disable inventory caching, or hook up a
distributed cache implementation.

### Inventory size

OCFL inventory files can grow quite large when an object has lots of
files and/or lots of versions. This problem is compounded by the fact
that a copy of the inventory must be persisted in every object version
directory. There are three things you can do to attempt to control
inventory bloat:

* Do not generate an excessive number of versions of an object
* Do not pretty print the inventory files (pretty printing is disabled
  by default)
* Use `sha256` instead of `sha512` for inventory content addressing.
`sha512` is the default and the spec recommended algorithm. On some
systems, `sha512` is faster than `sha256`, however, it requires twice
as much space to store. If you are concerned about space, you can
change the algorithm by setting
`OcflRepositoryBuilder.ocflConfig(config ->
config.setDefaultDigestAlgorithm(DigestAlgorithm.sha256))`. Note, this
only changes the digest algorithm used for *new* OCFL objects. It is
not possible to modify existing objects.

## APIs

### OcflRepository

See the Javadoc in `OcflRepository` for more detailed information.

* **putObject**: Stores a fully composed object in the repository. The
object's previous state is not carried forward. Only the files that
are present in the given path are considered to be part of the new
version. However, the files are still dedupped against previous
versions.
* **updateObject**: Unlike `putObject`, `updateObject` carries forward
the most recent object state, and allows you to make one-off changes
(adding, removing, moving, etc files) to an object without having the
entire object on hand.
* **getObject**: There are two different `getObject` implementations.
The first writes a complete copy of an object at a specified version
to a directory outside of the OCFL repository. The second returns an
object with lazy-loading references to all of the files that are part
of the specified object version.
* **describeObject**: Returns metadata about an object and all of its
  versions.
* **describeVersion**: Returns metadata about a specific version of an
  object.
* **fileChangeHistory**: Returns the change history for a specific
file within an object. This is useful for identifying at what point
specific files were changed.
* **containsObject**: Indicates whether the OCFL repository contains
  an object with the given id.
* **validateObject**: Validates an object against the OCFL 1.0 spec and
  returns a list of any errors or warnings found.
* **purgeObject**: Permanently removes an object from the repository.
  The object is NOT recoverable.
* **listObjectIds**: Returns a stream containing the ids of all of the
  objects in the repository. This API may be slow.
* **exportVersion**: Copies the entire contents of an OCFL object
  version directory to a location outside of the repository.
* **exportObject**: Copies the entire contents of an OCFL object
  directory to a location outside of the repository.
* **importVersion**: Imports an OCFL object version into the
  repository.
* **importObject**: Imports an entire OCFL object into the repository.
* **close**: Closes the repository, releasing its resources.

### OcflObjectUpdater

See the Javadoc in `OcflObjectUpdater` for more detailed information.

* **addPath**: Adds a file or directory to the object.
* **writeFile**: Adds a file to the object, using an InputStream as
  the source of the file.
* **removeFile**: Removes the file at the logical path from the
object. The file is not removed from storage and can be reinstated
later.
* **renameFile**: Renames a file at an existing logical path to a new
  logical path.
* **reinstateFile**: Restores a file that existed in a previous
  version of the object.
* **clearVersionState**: By default, `updateObject` carries forward
the current object state, calling `clearVersionState` clears
everything out of the new version, so that it behaves the same as
`putObject`.
* **addFileFixity**: Adds an entry to the object's `fixity` block.
* **clearFixityBlock**: Removes all of the entries from the object's
  `fixity` block.

### OcflOption

A number of the APIs accept optional `OcflOption` arguments.

* **OVERWRITE**: By default, `ocfl-java` will not overwrite files that
already exist within an object. If you want to overwrite a file, you
must specify `OcflOption.OVERWRITE` in the operation.
* **MOVE_SOURCE**: By default, `ocfl-java` copies source files into an
internal staging directory where it builds the new object version
before moving the version into the repository. Specifying
`OcflOption.MOVE_SOURCE` instructs `ocfl-java` to move the source
files into the staging directory instead of copying them.
* **NO_VALIDATION**: By default, `ocfl-java` will run validations on
objects and versions that are imported and exported from the
repository. This flag instructs it not to do these validations.

## Extensions

[OCFL extensions](https://github.com/OCFL/extensions) are additional
features that the community has specified that are outside of the
scope of the OCFL spec.

### Storage Layout Extensions

Storage layout extensions describe how OCFL object IDs should be mapped
to paths within the OCFL storage root. `ocfl-java` includes built-in
implementations of these extensions, but, you can override these
implementations or add new layout extensions by writing your own
implementations of `OcflStorageLayoutExtension` and registering the
extension by calling
`OcflExtensionRegistry.register("new-extension-name",
NewExtension.class)` **before** initializing your OCFL repository.

The following is a list of currently supported storage layout
extensions:

* [0002-flat-direct-storage-layout](https://ocfl.github.io/extensions/0002-flat-direct-storage-layout.html)
  * Configuration class: `FlatLayoutConfig`
  * Implementation class: `FlatLayoutExtension`
* [0003-hash-and-id-n-tuple-storage-layout](https://ocfl.github.io/extensions/0003-hash-and-id-n-tuple-storage-layout.html)
  * Configuration class: `HashedNTupleIdEncapsulationLayoutConfig`
  * Implementation class: `HashedNTupleIdEncapsulationLayoutExtension`
* [0004-hashed-n-tuple-storage-layout](https://ocfl.github.io/extensions/0004-hashed-n-tuple-storage-layout.html)
  * Configuration class: `HashedNTupleLayoutConfig`
  * Implementation class: `HashedNTupleLayoutExtension`

### Mutable HEAD Extension

The [mutable HEAD
extension](https://ocfl.github.io/extensions/0005-mutable-head.html)
enables an OCFL object to have a mutable HEAD version that is stored
inside of the object root. This version is **not** an official OCFL
version, and it is not recognized by clients that do not implement
this extension. This extension allows you to iteratively make changes
to an object without every change producing a new OCFL version. When
you are satisfied with the state of the object, the mutable HEAD
version should be committed, which moves it into an immutable OCFL
version that is recognized by all OCFL clients.

To enable this extension, call `OcflRepositoryBuilder.buildMutable()`.
Note, you do not need to enable the extension for reading. `ocfl-java`
will automatically read mutable HEAD versions that already exist.
However, it will not allow you to write to an object with a mutable
HEAD unless the extension is enabled.

#### APIs

See the Javadoc in `MutableOcflRepository` for more detailed
information.

* **stageChanges**: This method works the same as `updateObject`, but,
instead of making a new version, it updates or creates a mutable HEAD
version.
* **commitStagedChanges**: Converts a mutable HEAD version into an
  immutable OCFL version.
* **purgeStagedChanges**: Purges a mutable HEAD version without
  creating a new OCFL version.
* **hasStagedChanges**: Indicates if an object has a mutable HEAD.
