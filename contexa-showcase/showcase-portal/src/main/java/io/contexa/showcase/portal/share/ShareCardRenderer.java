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
import java.util.ArrayList;
import java.util.List;
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

    /**
     * The card's fixed words; the title is the pair's own question (H-09 #30), so no card claims what its pair does not
     * show (five verdicts, two look-alike requests).
     */
    private record Words(String me, String line) {
    }

    private static final Map<String, Words> WORDS = Map.of(
            "ko", new Words("나", "실제 실행 기록"),
            "en", new Words("Me", "Real recorded runs"));

    private static final int TITLE_LINES = 2;

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
     * @param question the pair's question in the card's language; null draws the demo name instead
     * @param mine     null when the visitor did not vote: the card then shows Contexa's score alone
     * @param host     the demo address shown at the bottom, for example demo.ctxa.ai
     */
    public byte[] render(String language, String question, Score mine, Score contexa, String host) {
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
            g.setFont(bold.deriveFont(44f));
            List<String> title = lines(question == null || question.isBlank() ? "Contexa Demo" : question, g,
                    WIDTH - 2 * MARGIN);
            for (int index = 0; index < title.size(); index++) {
                g.drawString(title.get(index), MARGIN, 206 + index * 58);
            }

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

    /** The title broken into at most two lines that fit the width, at spaces where it can; the rest is cut with "…". */
    static List<String> lines(String text, Graphics2D g, int width) {
        List<String> lines = new ArrayList<>();
        StringBuilder line = new StringBuilder();
        for (String word : text.trim().split("\\s+")) {
            String candidate = line.isEmpty() ? word : line + " " + word;
            if (g.getFontMetrics().stringWidth(candidate) <= width) {
                line.setLength(0);
                line.append(candidate);
                continue;
            }
            if (!line.isEmpty()) {
                lines.add(line.toString());
                line.setLength(0);
            }
            // A word wider than the line is broken by characters.
            for (char letter : word.toCharArray()) {
                if (g.getFontMetrics().stringWidth(line.toString() + letter) > width && !line.isEmpty()) {
                    lines.add(line.toString());
                    line.setLength(0);
                }
                line.append(letter);
            }
        }
        if (!line.isEmpty()) {
            lines.add(line.toString());
        }
        if (lines.size() <= TITLE_LINES) {
            return lines;
        }
        List<String> kept = new ArrayList<>(lines.subList(0, TITLE_LINES));
        StringBuilder last = new StringBuilder(kept.get(TITLE_LINES - 1));
        while (!last.isEmpty() && g.getFontMetrics().stringWidth(last + "…") > width) {
            last.setLength(last.length() - 1);
        }
        kept.set(TITLE_LINES - 1, last + "…");
        return kept;
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
