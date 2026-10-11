/*******************************************************************************
 * Copyright 2026 Karsten Philipp Boris Hahn
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package io.github.struppigel.tools.visualizer.render;

import io.github.struppigel.tools.visualizer.engine.ByteClass;

import java.awt.Color;

/**
 * The color formulas of the classic visualizer.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class VisualizerColors {

    private VisualizerColors() {
    }

    /**
     * Darkens a color by 30 per channel; channels below 0 wrap to 255. If the
     * result is black, which means caves, the start color is returned.
     *
     * @param color the color to change
     * @param start the color to use instead of black
     * @return the changed color
     */
    public static Color variate(Color color, Color start) {
        final int diff = 30;
        Color newColor = new Color(shiftColorPart(color.getRed() - diff), shiftColorPart(color.getGreen() - diff),
                shiftColorPart(color.getBlue() - diff));
        if (newColor.equals(Color.black)) {
            return start;
        }
        return newColor;
    }

    /**
     * Applies {@link #variate(Color, Color)} several times.
     *
     * @param color the color to change
     * @param start the color to use instead of black
     * @param times how often to change the color
     * @return the changed color
     */
    public static Color variate(Color color, Color start, int times) {
        Color result = color;
        for (int i = 0; i < times; i++) {
            result = variate(result, start);
        }
        return result;
    }

    private static int shiftColorPart(int colorPart) {
        if (colorPart < 0) {
            return 255;
        }
        if (colorPart > 255) {
            return 0;
        }
        return colorPart;
    }

    /**
     * Returns the color of an entropy: hue and saturation of the base color,
     * brightness of the entropy.
     *
     * @param base the entropy color
     * @param entropy the entropy from 0 to 1
     * @return the color of the entropy
     */
    public static Color entropyColor(Color base, double entropy) {
        return new Color(entropyRgb(hsb(base), entropy));
    }

    static int entropyRgb(float[] baseHsb, double entropy) {
        float brightness = (float) Math.max(0, Math.min(1, entropy));
        return 0xFF000000 | Color.HSBtoRGB(baseHsb[0], baseHsb[1], brightness);
    }

    /**
     * Returns the byte plot color of a byte value. 0x00 and 0xFF have their
     * own colors. ASCII bytes take hue and saturation of the visible or
     * invisible ASCII color and get brighter with the value, bytes above 127
     * those of the non-ASCII color.
     *
     * @param value the byte value from 0 to 255
     * @param minByte the color of 0x00
     * @param maxByte the color of 0xFF
     * @param visibleAscii the color of printable ASCII
     * @param invisibleAscii the color of ASCII control characters
     * @param nonAscii the color of bytes above 127
     * @return the color of the byte
     */
    public static Color bytePlotColor(int value, Color minByte, Color maxByte, Color visibleAscii,
                                      Color invisibleAscii, Color nonAscii) {
        int b = value & 0xFF;
        if (b == 0) return minByte;
        if (b == 0xFF) return maxByte;
        if (b <= 127) {
            float[] hsb = (b < 33 || b == 127) ? hsb(invisibleAscii) : hsb(visibleAscii);
            return Color.getHSBColor(hsb[0], hsb[1], b / (float) 127);
        }
        float[] hsb = hsb(nonAscii);
        return Color.getHSBColor(hsb[0], hsb[1], (b - 127) / (float) (255 - 127));
    }

    /**
     * Returns the byte plot color of the mean value of a byte class. Within a
     * class the color changes linearly with the value, so this is the mean
     * color of the bytes of the class.
     *
     * @param byteClass the class
     * @param meanValue the mean byte value of the class
     * @param minByte the color of 0x00
     * @param maxByte the color of 0xFF
     * @param visibleAscii the color of printable ASCII
     * @param invisibleAscii the color of ASCII control characters
     * @param nonAscii the color of bytes above 127
     * @return the color of the class
     */
    public static Color classColor(ByteClass byteClass, double meanValue, Color minByte, Color maxByte,
                                   Color visibleAscii, Color invisibleAscii, Color nonAscii) {
        switch (byteClass) {
            case ZERO:
                return minByte;
            case MAX:
                return maxByte;
            case PRINTABLE: {
                float[] hsb = hsb(visibleAscii);
                return Color.getHSBColor(hsb[0], hsb[1], clamp(meanValue / 127));
            }
            case CONTROL: {
                float[] hsb = hsb(invisibleAscii);
                return Color.getHSBColor(hsb[0], hsb[1], clamp(meanValue / 127));
            }
            default: {
                float[] hsb = hsb(nonAscii);
                return Color.getHSBColor(hsb[0], hsb[1], clamp((meanValue - 127) / (255 - 127)));
            }
        }
    }

    private static float clamp(double value) {
        return (float) Math.max(0, Math.min(1, value));
    }

    static float[] hsb(Color color) {
        return Color.RGBtoHSB(color.getRed(), color.getGreen(), color.getBlue(), null);
    }

    /**
     * Returns a color that is brighter or darker than the given one.
     *
     * @param color the color
     * @param amount from -1 (black) to 1 (white)
     * @return the shaded color
     */
    public static Color shade(Color color, double amount) {
        if (amount >= 0) {
            return new Color(lighten(color.getRed(), amount), lighten(color.getGreen(), amount),
                    lighten(color.getBlue(), amount));
        }
        double factor = 1 + amount;
        return new Color((int) Math.round(color.getRed() * factor), (int) Math.round(color.getGreen() * factor),
                (int) Math.round(color.getBlue() * factor));
    }

    private static int lighten(int channel, double amount) {
        return (int) Math.round(channel + (255 - channel) * amount);
    }

    /** opaque black text */
    public static final int BLACK_TEXT = 0xFF000000;
    /** opaque white text */
    public static final int WHITE_TEXT = 0xFFFFFFFF;

    /**
     * Returns the text color with the higher contrast on a background: black
     * if the WCAG relative luminance of the background is above 0.179,
     * otherwise white. The contrast ratio of the chosen color is at least 4.5.
     *
     * @param backgroundRgb the background color as int, alpha is ignored
     * @return {@link #BLACK_TEXT} or {@link #WHITE_TEXT}
     */
    public static int textRgbFor(int backgroundRgb) {
        return relativeLuminance(backgroundRgb) > 0.179 ? BLACK_TEXT : WHITE_TEXT;
    }

    /**
     * Returns the relative luminance of WCAG 2: the weighted sum of the
     * linearised sRGB channels.
     *
     * @param rgb a color as int, alpha is ignored
     * @return the relative luminance from 0 (black) to 1 (white)
     */
    public static double relativeLuminance(int rgb) {
        return 0.2126 * linear((rgb >> 16) & 0xFF) + 0.7152 * linear((rgb >> 8) & 0xFF)
                + 0.0722 * linear(rgb & 0xFF);
    }

    private static double linear(int channel) {
        double c = channel / 255.0;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }

    /**
     * Returns the contrast ratio of WCAG 2 between two colors, from 1 to 21.
     *
     * @param rgb1 a color as int
     * @param rgb2 another color as int
     * @return the contrast ratio
     */
    public static double contrastRatio(int rgb1, int rgb2) {
        double l1 = relativeLuminance(rgb1);
        double l2 = relativeLuminance(rgb2);
        return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    }

    /**
     * Returns a perceived brightness of the gamma-encoded channels. Use
     * {@link #relativeLuminance(int)} for contrast decisions.
     *
     * @param rgb a color as int
     * @return the brightness from 0 to 1
     */
    public static double luminance(int rgb) {
        int r = (rgb >> 16) & 0xFF;
        int g = (rgb >> 8) & 0xFF;
        int b = rgb & 0xFF;
        return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
    }
}
