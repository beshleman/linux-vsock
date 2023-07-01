/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef VSOCK_TEST_ZEROCOPY_H
#define VSOCK_TEST_ZEROCOPY_H
#include "util.h"

void test_stream_msg_zcopy_client(const struct test_opts *opts);
void test_stream_msg_zcopy_server(const struct test_opts *opts);

void test_seqpacket_msg_zcopy_client(const struct test_opts *opts);
void test_seqpacket_msg_zcopy_server(const struct test_opts *opts);

void test_stream_msg_zcopy_empty_errq_client(const struct test_opts *opts);
void test_stream_msg_zcopy_empty_errq_server(const struct test_opts *opts);

#endif /* VSOCK_TEST_ZEROCOPY_H */
