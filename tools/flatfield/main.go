//go:build ignore

// Command flatfield corrects a key-art render so its studio backdrop becomes
// the page colour.
//
// Run it when a new render is brought in from the website's art set:
//
//	go run tools/flatfield/main.go \
//	    ../../website/public/art/security.jpg \
//	    internal/assets/static/images/key-art-security.jpg
//
// Built behind the ignore tag: it is a developer utility that takes file paths
// straight off the command line, which is correct for a CLI and which gosec
// reasonably flags when it is compiled as part of an authentication service.
//
// The render's ground falls off across the frame -- measured at 4 luminance
// points below the page at bottom-left and 29 at top-right. That is a colour
// difference, and no amount of edge feathering hides one; it only decides where
// the difference sits. Correcting the illumination removes it.
//
// The field is fitted as a 2D quadratic over the border region, which is
// guaranteed to be backdrop, then extrapolated across the whole frame. A
// max-filter would have been simpler but breaks down in the middle of the
// subject, where there is no backdrop within any sane radius to sample.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"math"
	"os"
)

// quadratic basis at a normalised point.
func basis(x, y float64) [6]float64 {
	return [6]float64{1, x, y, x * x, x * y, y * y}
}

// solve returns the least-squares coefficients for A'A c = A'b, given the
// accumulated normal equations.
func solve(n [6][6]float64, rhs [6]float64) [6]float64 {
	var m [6][7]float64
	for i := 0; i < 6; i++ {
		copy(m[i][:6], n[i][:])
		m[i][6] = rhs[i]
	}
	for col := 0; col < 6; col++ {
		pivot := col
		for r := col + 1; r < 6; r++ {
			if math.Abs(m[r][col]) > math.Abs(m[pivot][col]) {
				pivot = r
			}
		}
		m[col], m[pivot] = m[pivot], m[col]
		if math.Abs(m[col][col]) < 1e-12 {
			continue
		}
		for r := 0; r < 6; r++ {
			if r == col {
				continue
			}
			f := m[r][col] / m[col][col]
			for c := col; c < 7; c++ {
				m[r][c] -= f * m[col][c]
			}
		}
	}
	var out [6]float64
	for i := 0; i < 6; i++ {
		if math.Abs(m[i][i]) > 1e-12 {
			out[i] = m[i][6] / m[i][i]
		}
	}
	return out
}

func main() {
	in, out := os.Args[1], os.Args[2]
	// Target is the page ground, #f6f4f8.
	target := [3]float64{246, 244, 248}

	f, err := os.Open(in)
	if err != nil {
		panic(err)
	}
	src, err := jpeg.Decode(f)
	if err != nil {
		panic(err)
	}
	_ = f.Close()

	b := src.Bounds()
	w, h := b.Dx(), b.Dy()

	// The border band that is certainly backdrop. The subject spans roughly
	// x 7-93% and y 24-80%, so these margins stay clear of it.
	isBorder := func(px, py int) bool {
		fx, fy := float64(px)/float64(w-1), float64(py)/float64(h-1)
		return fy < 0.18 || fy > 0.88 || fx < 0.05 || fx > 0.96
	}

	var coeffs [3][6]float64
	for ch := 0; ch < 3; ch++ {
		var n [6][6]float64
		var rhs [6]float64
		for py := 0; py < h; py++ {
			for px := 0; px < w; px++ {
				if !isBorder(px, py) {
					continue
				}
				r, g, bl, _ := src.At(b.Min.X+px, b.Min.Y+py).RGBA()
				v := []float64{float64(r >> 8), float64(g >> 8), float64(bl >> 8)}[ch]
				fx, fy := float64(px)/float64(w-1), float64(py)/float64(h-1)
				bs := basis(fx, fy)
				for i := 0; i < 6; i++ {
					for j := 0; j < 6; j++ {
						n[i][j] += bs[i] * bs[j]
					}
					rhs[i] += bs[i] * v
				}
			}
		}
		coeffs[ch] = solve(n, rhs)
	}

	fmt.Printf("fitted field, corners (r,g,b):\n")
	for _, p := range [][2]float64{{0, 0}, {1, 0}, {0, 1}, {1, 1}} {
		var v [3]float64
		for ch := 0; ch < 3; ch++ {
			bs := basis(p[0], p[1])
			for i := 0; i < 6; i++ {
				v[ch] += coeffs[ch][i] * bs[i]
			}
		}
		fmt.Printf("  (%.0f,%.0f) %.1f %.1f %.1f  -> gain %.3f %.3f %.3f\n",
			p[0], p[1], v[0], v[1], v[2], target[0]/v[0], target[1]/v[1], target[2]/v[2])
	}

	dst := image.NewRGBA(b)
	for py := 0; py < h; py++ {
		fy := float64(py) / float64(h-1)
		for px := 0; px < w; px++ {
			fx := float64(px) / float64(w-1)
			bs := basis(fx, fy)
			r, g, bl, _ := src.At(b.Min.X+px, b.Min.Y+py).RGBA()
			vals := [3]float64{float64(r >> 8), float64(g >> 8), float64(bl >> 8)}
			var o [3]uint8
			for ch := 0; ch < 3; ch++ {
				var field float64
				for i := 0; i < 6; i++ {
					field += coeffs[ch][i] * bs[i]
				}
				if field < 1 {
					field = 1
				}
				// Multiplicative, which is what illumination is: the subject is
				// corrected by the same factor as the ground beside it, so the
				// paper keeps its modelling instead of being flattened.
				v := vals[ch] * target[ch] / field
				if v < 0 {
					v = 0
				}
				if v > 255 {
					v = 255
				}
				o[ch] = uint8(v + 0.5)
			}
			dst.Set(b.Min.X+px, b.Min.Y+py, color.RGBA{o[0], o[1], o[2], 255})
		}
	}

	g, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	if err := jpeg.Encode(g, dst, &jpeg.Options{Quality: 88}); err != nil {
		panic(err)
	}
	if err := g.Close(); err != nil {
		panic(err)
	}
	fmt.Println("wrote", out)
}
