/*******************************************************************************
 * Copyright 2014 Katja Hahn
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
package io.github.struppigel.tools.visualizer;

import com.google.common.base.Preconditions;

import java.awt.image.BufferedImage;

/**
 * Utility methods for buffered images.
 * 
 * @author Katja Hahn
 * 
 */
public class ImageUtil {

    /**
     * Appends rightImage to the right side of leftImage.
     * <p>
     * The resulting image type is one of leftImage.
     * 
     * @param leftImage
     *            first image, must not be null
     * @param rightImage
     *            second image that is appended to the right side of leftImage,
     *            must not be null
     * @return appended image
     */
    public static BufferedImage appendImages(BufferedImage leftImage,
            BufferedImage rightImage) {
        Preconditions.checkNotNull(leftImage);
        Preconditions.checkNotNull(rightImage);
        int width = leftImage.getWidth() + rightImage.getWidth();
        int height = Math.max(leftImage.getHeight(), rightImage.getHeight());
        BufferedImage result = new BufferedImage(width, height,
                leftImage.getType());
        result.createGraphics().drawImage(leftImage, 0, 0, null);
        result.createGraphics().drawImage(rightImage, leftImage.getWidth(), 0, null);
        return result;
    }

}
