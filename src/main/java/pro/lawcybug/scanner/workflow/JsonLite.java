package pro.lawcybug.scanner.workflow;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, zero-dependency, FULLY recursive JSON parser (unlike
 * pro.lawcybug.scanner.rules.MiniJson, which is intentionally shallow and
 * package-private since it only needs to load rule files). This one backs
 * {@link ResponseSimilarityEngine} and the workflow engine generally, where
 * arbitrarily nested API response bodies are the norm.
 *
 * Not a general-purpose JSON library -- no streaming, no comments support,
 * no surrogate-pair edge cases beyond standard \\uXXXX escapes -- but
 * correct for well-formed JSON, which is what HTTP API responses are.
 */
final class JsonLite {

    private final String s;
    private int pos;

    private JsonLite(String s) {
        this.s = s;
    }

    static Object parse(String json) {
        JsonLite p = new JsonLite(json);
        p.skipWs();
        Object value = p.parseValue();
        p.skipWs();
        return value;
    }

    private Object parseValue() {
        skipWs();
        if (pos >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        char c = s.charAt(pos);
        switch (c) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': return parseString();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default: return parseNumber();
        }
    }

    private Map<String, Object> parseObject() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // '{'
        skipWs();
        if (peek() == '}') { pos++; return map; }
        while (true) {
            skipWs();
            String key = parseString();
            skipWs();
            if (peek() != ':') throw new IllegalArgumentException("Expected ':' at " + pos);
            pos++;
            Object value = parseValue();
            map.put(key, value);
            skipWs();
            char c = peek();
            if (c == ',') { pos++; continue; }
            if (c == '}') { pos++; break; }
            throw new IllegalArgumentException("Expected ',' or '}' at " + pos);
        }
        return map;
    }

    private List<Object> parseArray() {
        List<Object> list = new ArrayList<>();
        pos++; // '['
        skipWs();
        if (peek() == ']') { pos++; return list; }
        while (true) {
            Object value = parseValue();
            list.add(value);
            skipWs();
            char c = peek();
            if (c == ',') { pos++; continue; }
            if (c == ']') { pos++; break; }
            throw new IllegalArgumentException("Expected ',' or ']' at " + pos);
        }
        return list;
    }

    private String parseString() {
        if (peek() != '"') throw new IllegalArgumentException("Expected string at " + pos);
        pos++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = s.charAt(pos++);
            if (c == '"') break;
            if (c == '\\') {
                char esc = s.charAt(pos++);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        String hex = s.substring(pos, pos + 4);
                        sb.append((char) Integer.parseInt(hex, 16));
                        pos += 4;
                        break;
                    default: sb.append(esc);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private Object parseNumber() {
        int start = pos;
        if (peek() == '-') pos++;
        while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        boolean isDouble = false;
        if (pos < s.length() && s.charAt(pos) == '.') {
            isDouble = true;
            pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        }
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            isDouble = true;
            pos++;
            if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        }
        String num = s.substring(start, pos);
        if (num.isEmpty() || num.equals("-")) throw new IllegalArgumentException("Invalid number at " + start);
        return isDouble ? (Object) Double.parseDouble(num) : (Object) Long.parseLong(num);
    }

    private void expect(String literal) {
        if (pos + literal.length() > s.length() || !s.regionMatches(pos, literal, 0, literal.length())) {
            throw new IllegalArgumentException("Expected '" + literal + "' at " + pos);
        }
        pos += literal.length();
    }

    private char peek() {
        if (pos >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        return s.charAt(pos);
    }

    private void skipWs() {
        while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
    }
}
