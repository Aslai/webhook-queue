# Webhook Queue

This project is a simple, non-durable, authenticated webhook queue. It allows the hoster of the application to define some parameters for a webhook, and the application will allow clients to register themselves for listening asynchronously. I would strongly suggest that if you run this service for serious purposes, put it behind an HTTPS proxy, as everything is handled in plaintext.

I wrote it to interface with a webhook service that provides webhooks that are authenticated via an HTTP parameter using an HMAC with SHA-256. Adding more options than this is simple enough, however I've gotten it to the point where I personally need it. 

Yes, it violatese REST-ful principles by putting mutations on GET requests. I am fine with this.

## Dependencies

This application depends on `bottle`, and expects a Python 3.8 environment or newer. If you need to run it on an older version of Python, converting all of the `TypedDict`s to normal `dict`s should be sufficient.

## Configuration

There are a few configuration options for this application. Users with `"can_reload": true` specified in their options can trigger a configuration reload. Additionally, updated passwords trigger an immediate flush of a new configuration file to disk.

A sample configuration file would look like this (without the JS comments):

```js
{
    // Listen host and port for choosing where the server will listen to connections from
    "listen_host": "0.0.0.0",
    "listen_port": 8080,
    // The users array provides a set of all authorized users.
    "users": [
        {
            // The login name for the user.
            "name": "John Doe",
            // A hash for the user. The format is "<hash type>;<salt>;<hash>". The 'plain' hash type is
            // provided to allow the admin to bootstrap a user into the system. It is strongly encouraged
            // that you change your password once the application is running to switch over to a SHA-512
            // hash.
            "pass_hash": "plain;;insecure",
            // Whether this user can remotely trigger a reload via the reload endpoint
            "can_reload": false,
            // A whitelist of queue names that this user can listen to.
            "queues": [
                "foo"
            ]
        }
    ],
    // Queues describes all the valid queues that can receive messages.
    "queues": [
        {
            // The name of the queue. This will be used anywhere that the queue needs to be referred to,
            // such as in URLs or other parts of the configuration.
            "name": "foo",
            // If this option is provided as a non-empty array, then discard any messages that come from
            // an IP other than the given IPs. Note that this is fundamentally security through obscurity
            // and should be used in conjunction with the auth section.
            "whitelist_ip": ["127.0.0.1"],
            "auth": {
                // Authentication method. This must be provided for the auth block to be considered at all.
                // Format is "<process type>-<hash type>". Valid process types are: hmac, hash. Valid hash
                // types are: sha256, sha512, ... 
                "method": "hmac-sha256",
                // The key used for the hashing method, if applicable.
                "key": "12345",
                // The name of the HTTP header that will have whatever signature or secret.
                "header_name": "Foo-Auth"
            }
        }
    ],
    // The following fields describe queue limits. These can be put directly in a queue configuration to
    // override the global options.

    // The maximum number of messages that a queue can have before messages at the beginning will begin to
    // be dropped.
    "max_message_count": 100,
    // The max size, in bytes, that a message can be. Messages that are sent which exceed this size will be
    // dropped and all clients will be put into an error state.
    "max_message_size": 10000,
    // The max size, in bytes, that the sum of all messages in a queue can be. Messages at the beginning of
    // the queue will be dropped as needed to stay within this limit.
    "max_queue_size": 500000
}
```

A note about limits:

If at any point, the limits on a queue would affect the messages that a client can receive, the next read from a client will result in an error that indicates to the client that a full refresh of any dependent state might be necessary. The queue for that client will be discarded and started from the most recent message at the time of the failed read. This will happen if a message is dropped for size reasons, or if one or more messages that the client has yet to read rolls off the queue.

## API

The API is relatively simple. There are only two objects that can be returned from the server, and a small handful of endpoints.

### Authentication

There are two types of authentication. The webhook authentication as defined in the conf file, and user authentication. User authentication is just plaintext HTTP basic auth.

### Objects

#### MessageList

The `MessageList` object provides all webhook messages that have been queued up since the last request

```js
{
    // This is the unix timestamp that was recorded when the server started. This can be used to identify
    // the last restart time of the server, which can indicate missing messages
    "time": string,
    "current_message": int, // This is the ID of the most recent message in the queue. Mainly a diagnostic
    "messages": [
        {
            "id": int, // The internal ID of this message in the queue
            "message": string // The exact message that was sent in a webhook to the application
        }
    ]
}
```

#### Error

The `Error` object identifies a failure state

```js
{
    // The reason, if any, that this error was returned
    "message": string, 
    // If true, the application is suggesting that you should try and perform a full refresh of any state
    // that might depend on the stream of webhooks
    "refresh": bool 
}
```

### Endpoints

#### Enqueue webhook message

`POST /q/:name`

This is the target that the webhook should be aimed at. `:name` is the name of the queue as given in the configuration file.

This endpoint is only subject to the per-queue auth requirements and IP whitelist

Returns an empty body or `Error`

#### Get new webhook messages 

`GET /read/:client`

This will fetch all the webhook messages that have accumulated on a client since the last read

This endpoint is subject to user authentication.

Returns `MessageList` or `Error`

#### Listen to a queue

`GET /listen/:client/:queue`

This defines a new client name for a given queue and will begin to acccumulate messages. Client names are per-user unique. Attempting to listen with the same client name twice will result in an error if you do not unlisten between listen attempts. All clients and queues will be discarded when the server closes.

This endpoint is subject to user authentication.

Returns an empty body or `Error`


#### Unlisten to a queue

`GET /unlisten/:client`

This removes a client from a user's listen list, if possible.

This endpoint is subject to user authentication.

Returns an empty body or `Error`


#### Set password

`POST /setPassword`

Alters the current user's password and updates the configuration file.

This endpoint is subject to user authentication.

Returns an empty body or `Error`

#### Reload configuration

`POST /reload`

Does an in-place reload of the configuration file. Existing queues will not have their contents discarded, however their configuration will be altered if the configuration file for that queue was changed. Queues and users that are no longer in the configuration file will be dropped. If the reload fails, the operation will be aborted.

If a user is already listening to a queue when a reload occurs, the client will be put into a "disconnected" state if the queue is either removed or the user is no longer allowed to listen to that queue. You may unlisten to a disconnected client. Calling listen on a disconnected client will also succeed if it would have otherwise succeeded.

This endpoint is subject to user authentication, and that user must have "can_reload": true in their user settings

Returns an empty body or `Error`

#### Get server start time

`GET /time`

Returns the unix timestamp indicating the server start time as a scalar value.

No authentication required.