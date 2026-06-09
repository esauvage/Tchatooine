#include "videoencoder.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
#include <libavutil/imgutils.h>
#include <libavutil/opt.h>
#include <libswscale/swscale.h>
}

VideoEncoder::VideoEncoder() {}

void VideoEncoder::init() {
	const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_H264);

	_codecContext = avcodec_alloc_context3(codec);

	_codecContext->width = 640;
	_codecContext->height = 480;

	_codecContext->time_base = AVRational{1, 15};
	_codecContext->framerate = AVRational{15, 1};

	_codecContext->pix_fmt = AV_PIX_FMT_YUV420P;

	av_opt_set(_codecContext->priv_data,
			   "preset",
			   "veryfast",
			   0);

	avcodec_open2(_codecContext, codec, nullptr);
}

void VideoEncoder::encode(int width, int height) {
	AVFrame *frame = av_frame_alloc();

	frame->format = AV_PIX_FMT_YUV420P;
	frame->width  = width;
	frame->height = height;

	av_frame_get_buffer(frame, 32);
	uint8_t *src[] = {const_cast<uint8_t*>(image.bits())};
	int srcStride[] = {image.bytesPerLine()};

	sws_scale(_sws, src, srcStride, 0, height, frame->data, frame->linesize);
}