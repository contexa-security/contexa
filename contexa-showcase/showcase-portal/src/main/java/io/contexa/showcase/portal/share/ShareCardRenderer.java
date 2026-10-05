package io.contexa.showcase.portal.share;

import io.contexa.showcase.portal.share.ExperienceResult.Score;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.font.TextAttribute;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Map;

/**
 * Draws the share card (deck p.15): a 1200x630 PNG for link previews with the demo name, the title, the scores and
 * the demo address only. Nothing about the visitor is drawn. The glyphs come from the bundled Pretendard font (SIL OFL
 * 1.1, fonts/OFL.txt), so the image looks the same on every host.
 */
public class ShareCardRenderer {

    public static final int WIDTH = 1200;
    public static final int HEIGHT = 630;

    private static final Color BACKGROUND_TOP = new Color(0x1D2C4A);
    private static final Color BACKGROUND_BOTTOM = new Color(0x0E1726);
    private static final Color GOLD = new Color(0xD4AF5A);
    private static final Color TEXT = new Color(0xF4F1E8);
    private static final Color TEXT_BODY = new Color(0xE9E6DD);
    private static final Color TEXT_MUTED = new Color(0xA9B4C4);
    private static final Color TEXT_SUBTLE = new Color(0x8E9AAE);
    private static final int MARGIN = 88;

    /** The card's words; the share link carries no other text. */
    private record Words(String title, String me, String line) {
    }

    private static final Map<String, Words> WORDS = Map.of(
            "ko", new Words("같은 요청, 다섯 개의 판정", "나", "겉모습이 같은 두 요청 · 실제 실행 기록"),
            "en", new Words("Same request, five verdicts", "Me", "Two look-alike requests · real recorded runs"));

    private final Font bold;
    private final Font regular;

    public ShareCardRenderer() {
        this.bold = font("fonts/Pretendard-Bold.ttf");
        this.regular = font("fonts/Pretendard-Regular.ttf");
    }

    public static boolean supports(String language) {
        return WORDS.containsKey(language);
    }

    /**
     * @param mine null when the visitor did not vote: the card then shows Contexa's score alone
     * @param host the demo address shown at the bottom, for example demo.ctxa.ai
     */
    public byte[] render(String language, Score mine, Score contexa, String host) {
        Words words = WORDS.get(language);
        if (words == null) {
            throw new IllegalArgumentException("Unsupported card language");
        }
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_FRACTIONALMETRICS, RenderingHints.VALUE_FRACTIONALMETRICS_ON);
            g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g.setPaint(new GradientPaint(0, 0, BACKGROUND_TOP, WIDTH * 0.7f, HEIGHT, BACKGROUND_BOTTOM));
            g.fillRect(0, 0, WIDTH, HEIGHT);
            g.setColor(GOLD);
            g.fillRect(0, 0, 12, HEIGHT);

            g.setFont(bold.deriveFont(Map.of(TextAttribute.SIZE, 28f, TextAttribute.TRACKING, 0.16f)));
            g.drawString("CONTEXA DEMO", MARGIN, 128);

            g.setColor(TEXT);
            g.setFont(bold.deriveFont(64f));
            g.drawString(words.title(), MARGIN, 236);

            g.setFont(bold.deriveFont(84f));
            int x = MARGIN;
            int baseline = 392;
            if (mine != null) {
                String me = words.me() + " " + mine.hits() + "/" + mine.total();
                g.setColor(TEXT_BODY);
                g.drawString(me, x, baseline);
                x += g.getFontMetrics().stringWidth(me);
                String separator = "  ·  ";
                g.setColor(TEXT_SUBTLE);
                g.drawString(separator, x, baseline);
                x += g.getFontMetrics().stringWidth(separator);
            }
            g.setColor(GOLD);
            g.drawString("Contexa " + contexa.hits() + "/" + contexa.total(), x, baseline);

            g.setColor(TEXT_MUTED);
            g.setFont(regular.deriveFont(32f));
            g.drawString(words.line(), MARGIN, 462);

            g.setColor(TEXT_SUBTLE);
            g.setFont(regular.deriveFont(28f));
            g.drawString(host, MARGIN, HEIGHT - 72);
        } finally {
            g.dispose();
        }
        ByteArrayOutputStream png = new ByteArrayOutputStream();
        try {
            ImageIO.write(image, "png", png);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not encode the share card", e);
        }
        return png.toByteArray();
    }

    private static Font font(String resource) {
        try (InputStream in = ShareCardRenderer.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing font " + resource);
            }
            return Font.createFont(Font.TRUETYPE_FONT, in);
        } catch (IOException | FontFormatException e) {
            throw new IllegalStateException("Could not load font " + resource, e);
        }
    }
}
