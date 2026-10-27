import java.awt.*;
import java.awt.geom.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;
import java.util.List;
import javax.imageio.ImageIO;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

/**
 * Host-side renderer for the app's VectorDrawable XML (subset: M L H V C Q Z, fill/stroke). Used to look at the icons
 * and logo without a device, and to produce store graphics.
 *   java tools/IconPreview.java sheet <res-dir> <out.png>
 *   java tools/IconPreview.java store <res-dir> <out-dir>
 */
public class IconPreview {
    record Layer(Path2D shape, Color fill, Color stroke, float width, boolean evenOdd) {}

    static Color color(String s, double alpha) {
        if (s == null || s.isEmpty()) return null;
        long v = Long.parseLong(s.substring(1), 16);
        int a = s.length() == 9 ? (int) ((v >> 24) & 255) : 255;
        return new Color((int) ((v >> 16) & 255), (int) ((v >> 8) & 255), (int) (v & 255), (int) Math.round(a * alpha));
    }

    static Path2D parse(String d, boolean evenOdd) {
        Path2D.Double p = new Path2D.Double(evenOdd ? Path2D.WIND_EVEN_ODD : Path2D.WIND_NON_ZERO);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("([MLHVCQZmlhvcqz])|(-?[0-9]*\\.?[0-9]+(?:[eE][-+]?[0-9]+)?)").matcher(d);
        List<String> tok = new ArrayList<>();
        int last = 0;
        while (m.find()) { if (!d.substring(last, m.start()).trim().isEmpty() && !d.substring(last, m.start()).trim().equals(",")) throw new IllegalArgumentException("bad path data near: " + d.substring(last, m.start())); tok.add(m.group()); last = m.end(); }
        double x = 0, y = 0, sx = 0, sy = 0;
        char cmd = 0;
        int i = 0;
        while (i < tok.size()) {
            String t = tok.get(i);
            if (Character.isLetter(t.charAt(0))) { cmd = t.charAt(0); i++; if (cmd == 'Z' || cmd == 'z') { p.closePath(); x = sx; y = sy; } continue; }
            boolean rel = Character.isLowerCase(cmd);
            char c = Character.toUpperCase(cmd);
            int need = switch (c) { case 'M', 'L' -> 2; case 'H', 'V' -> 1; case 'Q' -> 4; case 'C' -> 6; default -> throw new IllegalArgumentException("command " + cmd); };
            if (i + need > tok.size()) throw new IllegalArgumentException("too few numbers for " + cmd);
            double[] a = new double[need];
            for (int k = 0; k < need; k++) { if (Character.isLetter(tok.get(i + k).charAt(0))) throw new IllegalArgumentException("letter inside numbers"); a[k] = Double.parseDouble(tok.get(i + k)); }
            i += need;
            double ox = rel ? x : 0, oy = rel ? y : 0;
            switch (c) {
                case 'M' -> { x = a[0] + ox; y = a[1] + oy; p.moveTo(x, y); sx = x; sy = y; cmd = rel ? 'l' : 'L'; }
                case 'L' -> { x = a[0] + ox; y = a[1] + oy; p.lineTo(x, y); }
                case 'H' -> { x = a[0] + ox; p.lineTo(x, y); }
                case 'V' -> { y = a[0] + oy; p.lineTo(x, y); }
                case 'Q' -> { p.quadTo(a[0] + ox, a[1] + oy, a[2] + ox, a[3] + oy); x = a[2] + ox; y = a[3] + oy; }
                case 'C' -> { p.curveTo(a[0] + ox, a[1] + oy, a[2] + ox, a[3] + oy, a[4] + ox, a[5] + oy); x = a[4] + ox; y = a[5] + oy; }
            }
        }
        return p;
    }

    static List<Layer> load(File f, Color tint) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f);
        NodeList nl = doc.getElementsByTagName("path");
        List<Layer> out = new ArrayList<>();
        String ns = "http://schemas.android.com/apk/res/android";
        for (int i = 0; i < nl.getLength(); i++) {
            Element e = (Element) nl.item(i);
            String d = e.getAttributeNS(ns, "pathData");
            if (d.isEmpty()) d = e.getAttribute("android:pathData");
            String fc = attr(e, "fillColor"), sc = attr(e, "strokeColor"), sw = attr(e, "strokeWidth"), ft = attr(e, "fillType");
            Color fill = color(fc, 1), stroke = color(sc, 1);
            if (tint != null) { if (fill != null) fill = new Color(tint.getRed(), tint.getGreen(), tint.getBlue(), fill.getAlpha()); if (stroke != null) stroke = new Color(tint.getRed(), tint.getGreen(), tint.getBlue(), stroke.getAlpha()); }
            out.add(new Layer(parse(d, "evenOdd".equals(ft)), fill, stroke, sw.isEmpty() ? 0 : Float.parseFloat(sw), "evenOdd".equals(ft)));
        }
        return out;
    }

    static String attr(Element e, String n) { String v = e.getAttributeNS("http://schemas.android.com/apk/res/android", n); return v.isEmpty() ? e.getAttribute("android:" + n) : v; }

    static void draw(Graphics2D g, List<Layer> layers, double x, double y, double size, double viewport) {
        AffineTransform old = g.getTransform();
        g.translate(x, y); g.scale(size / viewport, size / viewport);
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
        for (Layer l : layers) {
            if (l.fill != null) { g.setColor(l.fill); g.fill(l.shape); }
            if (l.stroke != null) { g.setColor(l.stroke); g.setStroke(new BasicStroke(l.width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)); g.draw(l.shape); }
        }
        g.setTransform(old);
    }

    public static void main(String[] a) throws Exception {
        System.setProperty("java.awt.headless", "true");
        File res = new File(a[1]);
        if (a[0].equals("check")) check(res);
        else if (a[0].equals("sheet")) sheet(res, new File(a[2])); else store(res, new File(a[2]));
    }

    /** Strictly parses every vector drawable. Bad path data would crash the app when the icon is first drawn, so fail the build here instead. */
    static void check(File res) throws Exception {
        File[] files = new File(res, "drawable").listFiles((d, n) -> n.endsWith(".xml"));
        int vectors = 0, paths = 0;
        for (File f : files) {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f);
            if (!doc.getDocumentElement().getTagName().equals("vector")) continue;
            vectors++;
            List<Layer> layers = load(f, null);
            if (layers.isEmpty()) throw new IllegalStateException(f.getName() + " has no paths");
            for (Layer l : layers) {
                paths++;
                if (l.fill == null && l.stroke == null) throw new IllegalStateException(f.getName() + ": path neither filled nor stroked");
                java.awt.geom.Rectangle2D b = l.shape.getBounds2D();
                if (!(b.getWidth() >= 0) || b.getMinX() < -1 || b.getMinY() < -1 || b.getMaxX() > 109 || b.getMaxY() > 109) throw new IllegalStateException(f.getName() + ": path leaves the drawing area " + b);
            }
        }
        System.out.println("PASS: " + vectors + " vector drawables / " + paths + " paths parse and stay inside the canvas");
    }

    static void sheet(File res, File out) throws Exception {
        File[] icons = new File(res, "drawable").listFiles((d, n) -> n.startsWith("ic_") && !n.startsWith("ic_launcher") && !n.equals("ic_logo.xml") && !n.equals("ic_stat_aegis.xml") && !n.equals("ic_aegis.xml") && n.endsWith(".xml"));
        Arrays.sort(icons);
        int cols = 7, cell = 120, rows = (icons.length + cols - 1) / cols;
        BufferedImage img = new BufferedImage(cols * cell * 2, rows * cell + 220, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(0x14202B)); g.fillRect(0, 0, cols * cell, img.getHeight());
        g.setColor(new Color(0xF3F7F5)); g.fillRect(cols * cell, 0, cols * cell, img.getHeight());
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        for (int i = 0; i < icons.length; i++) {
            int cx = (i % cols) * cell, cy = (i / cols) * cell;
            for (int side = 0; side < 2; side++) {
                Color tint = side == 0 ? new Color(0x6CE6B5) : new Color(0x006C4D);
                draw(g, load(icons[i], tint), side * cols * cell + cx + 28, cy + 12, 64, 24);
                g.setColor(side == 0 ? Color.LIGHT_GRAY : Color.DARK_GRAY); g.setFont(new Font("SansSerif", Font.PLAIN, 11));
                g.drawString(icons[i].getName().replace(".xml", ""), side * cols * cell + cx + 8, cy + 100);
            }
        }
        // small sizes (24dp-ish at 1x and 2x) to judge legibility
        int y0 = rows * cell + 10;
        for (int i = 0; i < icons.length && i < 22; i++) { draw(g, load(icons[i], new Color(0xE6EEF5)), 10 + i * 34, y0, 24, 24); draw(g, load(icons[i], new Color(0x14202B)), cols * cell + 10 + i * 34, y0, 24, 24); }
        // logo, adaptive-icon masks and notification icon
        File fg = new File(res, "drawable/ic_launcher_foreground.xml"), bg = new File(res, "drawable/ic_launcher_background.xml"), mono = new File(res, "drawable/ic_launcher_monochrome.xml"), stat = new File(res, "drawable/ic_stat_aegis.xml");
        int y1 = y0 + 50;
        Shape[] masks = { new Ellipse2D.Double(0, 0, 96, 96), new RoundRectangle2D.Double(0, 0, 96, 96, 40, 40), new RoundRectangle2D.Double(0, 0, 96, 96, 18, 18) };
        for (int m = 0; m < masks.length; m++) {
            BufferedImage ic = new BufferedImage(96, 96, BufferedImage.TYPE_INT_ARGB);
            Graphics2D ig = ic.createGraphics(); ig.setClip(masks[m]);
            draw(ig, load(bg, null), 0, 0, 96, 108); draw(ig, load(fg, null), 0, 0, 96, 108); ig.dispose();
            g.drawImage(ic, 10 + m * 110, y1, null);
        }
        draw(g, load(mono, new Color(0xE6EEF5)), 350, y1, 96, 108);
        draw(g, load(stat, new Color(0xFFFFFF)), 470, y1, 48, 108);
        g.setColor(new Color(0x14202B)); g.fillRect(cols * cell + 340, y1, 120, 96);
        draw(g, load(fg, null), cols * cell + 350, y1, 96, 108);
        g.dispose();
        ImageIO.write(img, "png", out);
        System.out.println("sheet: " + icons.length + " icons -> " + out);
    }

    static void store(File res, File outDir) throws Exception {
        outDir.mkdirs();
        List<Layer> bg = load(new File(res, "drawable/ic_launcher_background.xml"), null), fg = load(new File(res, "drawable/ic_launcher_foreground.xml"), null);
        // Play icon: 512 x 512, full bleed (Play applies the mask). The mark is scaled up so it fills about 60% of the canvas.
        BufferedImage icon = new BufferedImage(512, 512, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = icon.createGraphics();
        draw(g, bg, 0, 0, 512, 108); draw(g, fg, -102, -102, 716, 108); g.dispose();
        ImageIO.write(icon, "png", new File(outDir, "play-icon-512.png"));
        // Feature graphic 1024 x 500 (draft): dark field, mark, wordmark and the tagline.
        BufferedImage fgImg = new BufferedImage(1024, 500, BufferedImage.TYPE_INT_RGB);
        Graphics2D f = fgImg.createGraphics();
        f.setPaint(new GradientPaint(0, 0, new Color(0x0A1118), 1024, 500, new Color(0x14303A)));
        f.fillRect(0, 0, 1024, 500);
        f.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        draw(f, fg, 90, 70, 360, 108);
        f.setColor(new Color(0xE6EEF5)); f.setFont(new Font("SansSerif", Font.BOLD, 76));
        f.drawString("AEGIS", 470, 235);
        f.setColor(new Color(0x6CE6B5)); f.setFont(new Font("SansSerif", Font.PLAIN, 36));
        f.drawString("Pause. Check. Decide.", 474, 295);
        f.setColor(new Color(0xA0B8CC)); f.setFont(new Font("SansSerif", Font.PLAIN, 24));
        f.drawString("Links, messages and APK files,", 474, 350); f.drawString("checked on your phone.", 474, 384);
        f.dispose();
        ImageIO.write(fgImg, "png", new File(outDir, "play-feature-graphic-1024x500-DRAFT.png"));
        System.out.println("store assets -> " + outDir);
    }
}
