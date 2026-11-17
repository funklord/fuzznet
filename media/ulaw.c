/* G.711 mu-law: media/ulaw.h, fuzznet sec 1234. */
#include "ulaw.h"

#define BIAS 0x84
#define CLIP 32635

uint8_t fzn_ulaw_encode(int16_t sample)
{
	int s = sample, exponent = 7, mask;
	const int sign = s < 0 ? 0x80 : 0;

	if (s < 0)
		s = -s;
	if (s > CLIP)
		s = CLIP;
	s += BIAS;
	for (mask = 0x4000; !(s & mask) && exponent > 0; mask >>= 1)
		exponent--;
	return (uint8_t)~(sign | (exponent << 4) | ((s >> (exponent + 3)) & 0x0f));
}

int16_t fzn_ulaw_decode(uint8_t byte)
{
	const int u = ~byte & 0xff;
	const int exponent = (u >> 4) & 0x07, mantissa = u & 0x0f;
	const int s = (((mantissa << 3) + BIAS) << exponent) - BIAS;

	return (int16_t)((u & 0x80) ? -s : s);
}

void fzn_ulaw_encode_frame(const int16_t *pcm, size_t n, uint8_t *out)
{
	size_t i;

	for (i = 0; pcm && out && i < n; i++)
		out[i] = fzn_ulaw_encode(pcm[i]);
}

void fzn_ulaw_decode_frame(const uint8_t *in, size_t n, int16_t *pcm)
{
	size_t i;

	for (i = 0; in && pcm && i < n; i++)
		pcm[i] = fzn_ulaw_decode(in[i]);
}
