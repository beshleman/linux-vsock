// SPDX-License-Identifier: GPL-2.0-only
/* MSG_ZEROCOPY feature tests for vsock
 *
 * Copyright (C) 2023 SberDevices.
 *
 * Author: Arseniy Krasnov <AVKrasnov@sberdevices.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <poll.h>
#include <linux/errqueue.h>
#include <linux/kernel.h>
#include <error.h>
#include <errno.h>

#include "control.h"
#include "vsock_test_zerocopy.h"

#define PAGE_SIZE		4096

static struct vsock_test_data test_data_array[] = {
	/* Last element has non-page aligned size. */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ NULL, PAGE_SIZE },
			{ NULL, 200 }
		}
	},
	/* All elements have page aligned base and size. */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ NULL, PAGE_SIZE * 2 },
			{ NULL, PAGE_SIZE * 3 }
		}
	},
	/* All elements have page aligned base and size. But
	 * data length is bigger than 64Kb.
	 */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE * 16 },
			{ NULL, PAGE_SIZE * 16 },
			{ NULL, PAGE_SIZE * 16 }
		}
	},
	/* All elements have page aligned base and size. */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ NULL, PAGE_SIZE },
			{ NULL, PAGE_SIZE }
		}
	},
	/* Middle element has non-page aligned size. */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ NULL, 100 },
			{ NULL, PAGE_SIZE }
		}
	},
	/* Middle element has both non-page aligned base and size. */
	{
		.zerocopied = true,
		.completion = true,
		.sendmsg_errno = 0,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ (void *)1, 100 },
			{ NULL, PAGE_SIZE }
		}
	},
	/* Middle element is unmapped. */
	{
		.zerocopied = false,
		.completion = false,
		.sendmsg_errno = ENOMEM,
		.vecs_cnt = 3,
		{
			{ NULL, PAGE_SIZE },
			{ MAP_FAILED, PAGE_SIZE },
			{ NULL, PAGE_SIZE }
		}
	},
	/* Valid data, but SO_ZEROCOPY is off. */
	{
		.zerocopied = true,
		.completion = false,
		.sendmsg_errno = 0,
		.vecs_cnt = 1,
		{
			{ NULL, PAGE_SIZE }
		}
	},
};

static void __test_msg_zerocopy_client(const struct test_opts *opts,
				       const struct vsock_test_data *test_data,
				       bool sock_seqpacket)
{
	struct msghdr msg = { 0 };
	ssize_t sendmsg_res;
	struct iovec *iovec;
	int fd;

	if (sock_seqpacket)
		fd = vsock_seqpacket_connect(opts->peer_cid, 1234);
	else
		fd = vsock_stream_connect(opts->peer_cid, 1234);

	if (fd < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	if (test_data->completion)
		enable_so_zerocopy(fd);

	iovec = iovec_from_test_data(test_data);

	msg.msg_iov = iovec;
	msg.msg_iovlen = test_data->vecs_cnt;

	errno = 0;

	sendmsg_res = sendmsg(fd, &msg, MSG_ZEROCOPY);
	if (errno != test_data->sendmsg_errno) {
		fprintf(stderr, "expected 'errno' == %i, got %i\n",
			test_data->sendmsg_errno, errno);
		exit(EXIT_FAILURE);
	}

	if (!errno) {
		if (sendmsg_res != iovec_bytes(iovec, test_data->vecs_cnt)) {
			fprintf(stderr, "expected 'sendmsg()' == %li, got %li\n",
				iovec_bytes(iovec, test_data->vecs_cnt),
				sendmsg_res);
			exit(EXIT_FAILURE);
		}
	}

	vsock_recv_completion(fd, test_data->zerocopied, test_data->completion);

	if (test_data->sendmsg_errno == 0)
		control_writeulong(iovec_hash_djb2(iovec, test_data->vecs_cnt));
	else
		control_writeulong(0);

	control_writeln("DONE");
	free_iovec_test_data(test_data, iovec);
	close(fd);
}

void test_stream_msg_zcopy_client(const struct test_opts *opts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_data_array); i++)
		__test_msg_zerocopy_client(opts, &test_data_array[i], false);
}

void test_seqpacket_msg_zcopy_client(const struct test_opts *opts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_data_array); i++)
		__test_msg_zerocopy_client(opts, &test_data_array[i], true);
}

static void __test_stream_server(const struct test_opts *opts,
				 const struct vsock_test_data *test_data,
				 bool sock_seqpacket)
{
	unsigned long remote_hash;
	unsigned long local_hash;
	ssize_t total_bytes_rec;
	unsigned char *data;
	size_t data_len;
	int fd;

	if (sock_seqpacket)
		fd = vsock_seqpacket_accept(VMADDR_CID_ANY, 1234, NULL);
	else
		fd = vsock_stream_accept(VMADDR_CID_ANY, 1234, NULL);

	if (fd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	data_len = iovec_bytes(test_data->vecs, test_data->vecs_cnt);

	data = malloc(data_len);
	if (!data) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	total_bytes_rec = 0;

	while (total_bytes_rec != data_len) {
		ssize_t bytes_rec;

		bytes_rec = read(fd, data + total_bytes_rec,
				 data_len - total_bytes_rec);
		if (bytes_rec <= 0)
			break;

		total_bytes_rec += bytes_rec;
	}

	if (test_data->sendmsg_errno == 0)
		local_hash = hash_djb2(data, data_len);
	else
		local_hash = 0;

	free(data);

	/* Waiting for some result. */
	remote_hash = control_readulong();
	if (remote_hash != local_hash) {
		fprintf(stderr, "hash mismatch\n");
		exit(EXIT_FAILURE);
	}

	control_expectln("DONE");
	close(fd);
}

void test_stream_msg_zcopy_server(const struct test_opts *opts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_data_array); i++)
		__test_stream_server(opts, &test_data_array[i], false);
}

void test_seqpacket_msg_zcopy_server(const struct test_opts *opts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(test_data_array); i++)
		__test_stream_server(opts, &test_data_array[i], true);
}

void test_stream_msg_zcopy_empty_errq_client(const struct test_opts *opts)
{
	struct msghdr msg = { 0 };
	char cmsg_data[128];
	ssize_t res;
	int fd;

	fd = vsock_stream_connect(opts->peer_cid, 1234);
	if (fd < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	msg.msg_control = cmsg_data;
	msg.msg_controllen = sizeof(cmsg_data);

	res = recvmsg(fd, &msg, MSG_ERRQUEUE);
	if (res != -1) {
		fprintf(stderr, "expected 'recvmsg(2)' failure, got %zi\n",
			res);
		exit(EXIT_FAILURE);
	}

	control_writeln("DONE");
	close(fd);
}

void test_stream_msg_zcopy_empty_errq_server(const struct test_opts *opts)
{
	int fd;

	fd = vsock_stream_accept(VMADDR_CID_ANY, 1234, NULL);
	if (fd < 0) {
		perror("accept");
		exit(EXIT_FAILURE);
	}

	control_expectln("DONE");
	close(fd);
}
