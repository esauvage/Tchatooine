#ifndef VIDEOENCODER_H
#define VIDEOENCODER_H

struct AVCodecContext;

class VideoEncoder
{
public:
	VideoEncoder();
	void encode(int width, int height);
	void init();
private:
	AVCodecContext * _codecContext;
};

#endif // VIDEOENCODER_H
