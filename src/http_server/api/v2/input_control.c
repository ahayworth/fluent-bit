/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_sds.h>
#include "input_control.h"

#include <fluent-bit/flb_http_server.h>

/*
 * Find an input instance by name (either alias or plugin name).
 * Returns the input instance if found, NULL otherwise.
 */
static struct flb_input_instance *find_input_by_name(const char *name,
                                                      struct flb_config *config)
{
    struct mk_list *head;
    struct flb_input_instance *ins;
    const char *ins_name;

    if (!name || !config) {
        return NULL;
    }

    mk_list_foreach(head, &config->inputs) {
        ins = mk_list_entry(head, struct flb_input_instance, _head);
        ins_name = flb_input_name(ins);

        if (ins_name && strcmp(ins_name, name) == 0) {
            return ins;
        }
    }

    return NULL;
}

/*
 * Extract input name from the URI path.
 * Expected format: /api/v2/input/{input_name}/pause or /api/v2/input/{input_name}/resume
 * Returns a newly allocated string with the input name, or NULL on error.
 */
static flb_sds_t extract_input_name_from_uri(const char *uri)
{
    const char *prefix = "/api/v2/input/";
    const char *start;
    const char *end;
    flb_sds_t name;
    size_t prefix_len;
    size_t name_len;

    if (!uri) {
        return NULL;
    }

    /* Check if URI starts with the expected prefix */
    prefix_len = strlen(prefix);
    if (strncmp(uri, prefix, prefix_len) != 0) {
        return NULL;
    }

    /* Find the start of the input name */
    start = uri + prefix_len;

    /* Find the end of the input name (next slash) */
    end = strchr(start, '/');
    if (!end) {
        return NULL;
    }

    /* Calculate name length */
    name_len = end - start;
    if (name_len == 0) {
        return NULL;
    }

    /* Allocate and copy the name */
    name = flb_sds_create_len(start, name_len);
    return name;
}

/*
 * Send a JSON response with a message and status code
 */
static void send_json_response(mk_request_t *request, int http_status,
                                const char *operation, const char *message,
                                const char *input_name)
{
    flb_sds_t out_buf;
    size_t out_size;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    /* Initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /* Create response map */
    msgpack_pack_map(&mp_pck, 3);

    /* operation field */
    msgpack_pack_str(&mp_pck, 9);
    msgpack_pack_str_body(&mp_pck, "operation", 9);
    msgpack_pack_str(&mp_pck, strlen(operation));
    msgpack_pack_str_body(&mp_pck, operation, strlen(operation));

    /* status field */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "status", 6);
    msgpack_pack_str(&mp_pck, strlen(message));
    msgpack_pack_str_body(&mp_pck, message, strlen(message));

    /* input field */
    msgpack_pack_str(&mp_pck, 5);
    msgpack_pack_str_body(&mp_pck, "input", 5);
    if (input_name) {
        msgpack_pack_str(&mp_pck, strlen(input_name));
        msgpack_pack_str_body(&mp_pck, input_name, strlen(input_name));
    }
    else {
        msgpack_pack_nil(&mp_pck);
    }

    /* Export to JSON */
    out_buf = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (!out_buf) {
        mk_http_status(request, 500);
        mk_http_done(request);
        return;
    }
    out_size = flb_sds_len(out_buf);

    mk_http_status(request, http_status);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_JSON);
    mk_http_send(request, out_buf, out_size, NULL);
    mk_http_done(request);

    flb_sds_destroy(out_buf);
}

/*
 * Handle pause request for a specific input
 */
static void handle_input_pause(mk_request_t *request, struct flb_config *config)
{
    flb_sds_t input_name;
    struct flb_input_instance *ins;
    int ret;

    /* Extract input name from URI */
    input_name = extract_input_name_from_uri(request->uri.data);
    if (!input_name) {
        send_json_response(request, 400, "pause", "invalid URI format", NULL);
        return;
    }

    /* Find the input instance */
    ins = find_input_by_name(input_name, config);
    if (!ins) {
        send_json_response(request, 404, "pause", "input not found", input_name);
        flb_sds_destroy(input_name);
        return;
    }

    /* Pause the input */
    ret = flb_input_pause(ins);
    if (ret == -1) {
        send_json_response(request, 400, "pause", "already paused or cannot pause", input_name);
        flb_sds_destroy(input_name);
        return;
    }

    flb_info("[http] input '%s' paused via API", input_name);
    send_json_response(request, 200, "pause", "success", input_name);
    flb_sds_destroy(input_name);
}

/*
 * Handle resume request for a specific input
 */
static void handle_input_resume(mk_request_t *request, struct flb_config *config)
{
    flb_sds_t input_name;
    struct flb_input_instance *ins;

    /* Extract input name from URI */
    input_name = extract_input_name_from_uri(request->uri.data);
    if (!input_name) {
        send_json_response(request, 400, "resume", "invalid URI format", NULL);
        return;
    }

    /* Find the input instance */
    ins = find_input_by_name(input_name, config);
    if (!ins) {
        send_json_response(request, 404, "resume", "input not found", input_name);
        flb_sds_destroy(input_name);
        return;
    }

    /* Resume the input */
    flb_input_resume(ins);

    flb_info("[http] input '%s' resumed via API", input_name);
    send_json_response(request, 200, "resume", "success", input_name);
    flb_sds_destroy(input_name);
}

/*
 * Main callback for input pause endpoint
 */
static void cb_input_pause(mk_request_t *request, void *data)
{
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    if (request->method == MK_METHOD_POST || request->method == MK_METHOD_PUT) {
        handle_input_pause(request, config);
    }
    else {
        mk_http_status(request, 405);  /* Method Not Allowed */
        mk_http_done(request);
    }
}

/*
 * Main callback for input resume endpoint
 */
static void cb_input_resume(mk_request_t *request, void *data)
{
    struct flb_hs *hs = data;
    struct flb_config *config = hs->config;

    if (request->method == MK_METHOD_POST || request->method == MK_METHOD_PUT) {
        handle_input_resume(request, config);
    }
    else {
        mk_http_status(request, 405);  /* Method Not Allowed */
        mk_http_done(request);
    }
}

/*
 * Register input control endpoints
 */
int api_v2_input_control(struct flb_hs *hs)
{
    /* Register pause endpoint - matches /api/v2/input/{input_name}/pause */
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v2/input/*/pause", cb_input_pause, hs);

    /* Register resume endpoint - matches /api/v2/input/{input_name}/resume */
    mk_vhost_handler(hs->ctx, hs->vid, "/api/v2/input/*/resume", cb_input_resume, hs);

    return 0;
}
