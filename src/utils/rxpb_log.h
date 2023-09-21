/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#ifndef _INCLUDE_PL_LOG_H_
#define _INCLUDE_PL_LOG_H_

#include "conf.h"

enum rxpb_log_level {
	RXPB_LOG_LEVEL_ERROR,
	RXPB_LOG_LEVEL_WARNING,
	RXPB_LOG_LEVEL_INFO,
	RXPB_LOG_LEVEL_ALERT,
};

void rxpb_log(rb_conf *run_conf, enum rxpb_log_level level, const char *message, ...);

#define PL_LOG(run_conf, level, format...)		rxpb_log(run_conf, RXPB_LOG_LEVEL_##level, format)

#define RXPB_LOG_ERR(format...)			PL_LOG(NULL, ERROR, format)
#define RXPB_LOG_WARN(format...)		PL_LOG(NULL, WARNING, format)
#define RXPB_LOG_INFO(format...)		PL_LOG(NULL, INFO, format)
#define RXPB_LOG_ALERT(format...)		PL_LOG(NULL, ALERT, format)
#define RXPB_LOG_WARN_REC(run_conf, format...)	PL_LOG(run_conf, WARNING, format)

#define PL_LOG_ERR(format...)			PL_LOG(NULL, ERROR, format)
#define PL_LOG_WARN(format...)		PL_LOG(NULL, WARNING, format)
#define PL_LOG_INFO(format...)		PL_LOG(NULL, INFO, format)
#define PL_LOG_ALERT(format...)		PL_LOG(NULL, ALERT, format)
#define PL_LOG_WARN_REC(run_conf, format...)	PL_LOG(run_conf, WARNING, format)

#endif /* _INCLUDE_RXPB_LOG_H_ */
