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

import java.awt.Color;
import java.util.Objects;

/**
 * One line of a legend: a title, or a label with a color sample.
 *
 * @author Karsten Philipp Boris Hahn
 */
public final class LegendEntry {

    private final String label;
    private final Color color;
    private final boolean title;
    private final boolean outlined;

    private LegendEntry(String label, Color color, boolean title, boolean outlined) {
        this.label = Objects.requireNonNull(label);
        this.color = Objects.requireNonNull(color);
        this.title = title;
        this.outlined = outlined;
    }

    /**
     * @param label the title text
     * @return a title entry
     */
    public static LegendEntry title(String label) {
        return new LegendEntry(label, Color.lightGray, true, false);
    }

    /**
     * @param label the label
     * @param color the color sample
     * @param outlined true if the sample has an outline, which marks structures
     *            that are drawn inset
     * @return a legend entry
     */
    public static LegendEntry entry(String label, Color color, boolean outlined) {
        return new LegendEntry(label, color, false, outlined);
    }

    /**
     * @return the label or title text
     */
    public String getLabel() {
        return label;
    }

    /**
     * @return the color of the sample, or the text color of a title
     */
    public Color getColor() {
        return color;
    }

    /**
     * @return true if this is a title
     */
    public boolean isTitle() {
        return title;
    }

    /**
     * @return true if the sample has an outline
     */
    public boolean isOutlined() {
        return outlined;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LegendEntry)) return false;
        LegendEntry that = (LegendEntry) o;
        return title == that.title && outlined == that.outlined && label.equals(that.label)
                && color.equals(that.color);
    }

    @Override
    public int hashCode() {
        return Objects.hash(label, color, title, outlined);
    }

    @Override
    public String toString() {
        return title ? "[" + label + "]" : label + " #" + Integer.toHexString(color.getRGB() & 0xFFFFFF);
    }
}
