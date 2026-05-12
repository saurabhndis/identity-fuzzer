/*
 * set_tos_napi.c — Native N-API addon for setting IP_TOS/DSCP on TCP sockets
 *
 * This addon provides two functions:
 *   setTOS(fd, tosValue)        — Set IP_TOS on an existing socket fd
 *   createSocketWithTOS(tosValue) — Create a new TCP socket with TOS pre-set
 *
 * Compile:
 *   gcc -shared -fPIC -o set_tos_napi.node set_tos_napi.c -I$(node -e "console.log(require('path').dirname(require.resolve('node-api-headers/include/node_api.h')) || '/usr/include/node')")
 *
 * Or simply:
 *   gcc -shared -fPIC -o set_tos_napi.node set_tos_napi.c -I/usr/include/node
 */

#include <node_api.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/*
 * setTOS(fd, tosValue) — Set IP_TOS on an existing socket fd
 * Returns the readback TOS value on success, -1 on failure
 */
static napi_value SetTOS(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    int32_t fd, tos;
    napi_get_value_int32(env, args[0], &fd);
    napi_get_value_int32(env, args[1], &tos);

    int result = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    int readback = -1;
    if (result == 0) {
        socklen_t len = sizeof(readback);
        getsockopt(fd, IPPROTO_IP, IP_TOS, &readback, &len);
    }

    napi_value ret;
    napi_create_int32(env, readback, &ret);
    return ret;
}

/*
 * createSocketWithTOS(tosValue) — Create a TCP socket with TOS pre-set
 * Returns the fd on success, negative errno on failure
 *
 * The socket is created with:
 *   - IP_TOS set to tosValue (so SYN packet will have DSCP)
 *   - TCP_NODELAY enabled
 *   - O_NONBLOCK set (for Node.js compatibility)
 */
static napi_value CreateSocketWithTOS(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    int32_t tos;
    napi_get_value_int32(env, args[0], &tos);

    /* Create TCP socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        napi_value ret;
        napi_create_int32(env, -errno, &ret);
        return ret;
    }

    /* Set TOS BEFORE connect — this marks the SYN packet */
    if (tos > 0) {
        setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    }

    /* Set TCP_NODELAY */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    /* Make non-blocking for Node.js compatibility */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* Clear CLOEXEC so fd survives if needed */
    int fdflags = fcntl(fd, F_GETFD, 0);
    fcntl(fd, F_SETFD, fdflags & ~FD_CLOEXEC);

    napi_value ret;
    napi_create_int32(env, fd, &ret);
    return ret;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn1, fn2;
    napi_create_function(env, NULL, 0, SetTOS, NULL, &fn1);
    napi_set_named_property(env, exports, "setTOS", fn1);
    napi_create_function(env, NULL, 0, CreateSocketWithTOS, NULL, &fn2);
    napi_set_named_property(env, exports, "createSocketWithTOS", fn2);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
