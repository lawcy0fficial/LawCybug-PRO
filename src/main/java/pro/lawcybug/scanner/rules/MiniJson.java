package pro.lawcybug.scanner.rules;

import java.util.*;

/**
 * Zero-dependency minimal JSON parser sufficient for loading rule files.
 * Parses a JSON object or array of objects into Map/List/String/Number/Boolean.
 * Does not handle deeply-nested structures beyond 2 levels, but that's all
 * our rule format requires.
 *
 * Intentionally keeps external dependency count at zero -- the pom.xml
 * has no runtime dependencies, so this is compile-anywhere, ship-anywhere.
 */
final class MiniJson {

    private MiniJson() {}

    /**
     * Parse a rule file that is either a single JSON object or an array of
     * JSON objects. Returns a List<Map<String,Object>> in both cases.
     */
    static List<Map<String, Object>> parseRulesList(String json) {
        String trimmed = json.trim();
        if (trimmed.startsWith("[")) {
            return parseArray(trimmed);
        } else if (trimmed.startsWith("{")) {
            return List.of(parseObject(trimmed));
        } else {
            throw new IllegalArgumentException("Expected a JSON object or array");
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> parseArray(String json) {
        List<Object> raw = (List<Object>) parseValue(json.trim());
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : raw) {
            if (item instanceof Map<?,?> m) {
                result.add((Map<String, Object>) m);
            }
        }
        return result;
    }

    private static Map<String, Object> parseObject(String json) {
        State s = new State(json.trim());
        return readObject(s);
    }

    private static Object parseValue(String json) {
        State s = new State(json.trim());
        return readValue(s);
    }

    private static Object readValue(State s) {
        s.skipWs();
        if (s.eof()) return null;
        char c = s.peek();
        if (c == '{') return readObject(s);
        if (c == '[') return readList(s);
        if (c == '"') return readString(s);
        if (c == 't') { s.advance(4); return Boolean.TRUE; }
        if (c == 'f') { s.advance(5); return Boolean.FALSE; }
        if (c == 'n') { s.advance(4); return null; }
        return readNumber(s);
    }

    private static Map<String, Object> readObject(State s) {
        s.expect('{');
        Map<String, Object> map = new LinkedHashMap<>();
        s.skipWs();
        if (s.peek() == '}') { s.pos++; return map; }
        while (!s.eof()) {
            s.skipWs();
            String key = readString(s);
            s.skipWs(); s.expect(':');
            Object val = readValue(s);
            map.put(key, val);
            s.skipWs();
            if (s.peek() == ',') { s.pos++; continue; }
            if (s.peek() == '}') { s.pos++; break; }
        }
        return map;
    }

    private static List<Object> readList(State s) {
        s.expect('[');
        List<Object> list = new ArrayList<>();
        s.skipWs();
        if (s.peek() == ']') { s.pos++; return list; }
        while (!s.eof()) {
            list.add(readValue(s));
            s.skipWs();
            if (s.peek() == ',') { s.pos++; continue; }
            if (s.peek() == ']') { s.pos++; break; }
        }
        return list;
    }

    private static String readString(State s) {
        s.expect('"');
        StringBuilder sb = new StringBuilder();
        while (!s.eof()) {
            char c = s.next();
            if (c == '"') break;
            if (c == '\\') {
                if (s.eof()) break;
                char esc = s.next();
                switch (esc) {
                    case '"'  -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/'  -> sb.append('/');
                    case 'n'  -> sb.append('\n');
                    case 'r'  -> sb.append('\r');
                    case 't'  -> sb.append('\t');
                    case 'b'  -> sb.append('\b');
                    case 'f'  -> sb.append('\f');
                    case 'u'  -> {
                        String hex = s.take(4);
                        sb.append((char) Integer.parseInt(hex, 16));
                    }
                    default   -> sb.append(esc);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static Object readNumber(State s) {
        StringBuilder sb = new StringBuilder();
        while (!s.eof() && "-0123456789.eE+".indexOf(s.peek()) >= 0) {
            sb.append(s.next());
        }
        String n = sb.toString();
        try {
            if (n.contains(".") || n.contains("e") || n.contains("E")) {
                return Double.parseDouble(n);
            }
            return Long.parseLong(n);
        } catch (NumberFormatException e) {
            return n;
        }
    }

    private static class State {
        final String src;
        int pos;

        State(String src) {
            this.src = src;
        }

        boolean eof() { return pos >= src.length(); }

        char peek() { return eof() ? 0 : src.charAt(pos); }

        char next() { return eof() ? 0 : src.charAt(pos++); }

        void advance(int n) { pos = Math.min(pos + n, src.length()); }

        void expect(char c) {
            if (peek() != c) throw new IllegalStateException("Expected '" + c + "' at pos " + pos + " got '" + peek() + "'");
            pos++;
        }

        void skipWs() {
            while (!eof() && Character.isWhitespace(src.charAt(pos))) pos++;
        }

        String take(int n) {
            String s = src.substring(pos, Math.min(pos + n, src.length()));
            pos += n;
            return s;
        }
    }
}
