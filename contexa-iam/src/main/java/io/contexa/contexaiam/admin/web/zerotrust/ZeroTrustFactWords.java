/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexaiam.admin.web.zerotrust;

import io.contexa.contexacore.autonomous.context.decision.DecisionFactsResolver;
import org.springframework.context.MessageSource;

import java.time.DayOfWeek;
import java.time.format.TextStyle;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * K122, K127: the words of a fact a reason cites, in the decision detail and its preview. The engine gives the model
 * each fact in its own notation, codes included ({@code action EXPORT against the scope group's actions (READ)},
 * {@code device Firefox/118 on LINUX seen 0 of 1}, {@code 5th EXPORT in this session}); the administrator reads every
 * kind of fact in plain words of the request's language: an action, a resource class, an operating system and a login
 * by their words, a code of the host (a business category, a record state, a ticket kind) by the word a message gives
 * it or else by its code in words. The notation the model reads is not changed. A part this reads no notation of keeps
 * its text with its engine words in words; a value the decision summary cut short ends with an ellipsis.
 */
final class ZeroTrustFactWords {

    private static final String F = "zt.console.ui.decision.fact.";
    private static final String RS = F + "roleScope.";
    private static final String DIMENSION = "zt.console.ui.decision.dimension.";
    private static final String ACTION_WORD = "zt.console.ui.decision.value.action.";
    private static final String CATEGORY_WORD = "zt.console.ui.decision.value.category.";
    private static final String CLASS_WORD = "zt.console.ui.decisions.resourceClass.";
    private static final String OS_WORD = "zt.console.ui.decision.value.os.";
    private static final String LOGIN_WORD = "zt.console.ui.decision.value.login.";
    private static final String STATUS_WORD = "zt.console.ui.decision.value.recordStatus.";
    private static final String TICKET_KIND_WORD = "zt.console.ui.decision.value.ticketKind.";
    private static final String ZONE_WORD = "zt.console.ui.decision.value.zone.";

    /** The length the decision summary keeps of a fact's value ({@code DecisionConsoleColumns}): one as long was cut. */
    static final int KEPT_LENGTH = 300;
    /** The engine's parts of a fact, joined by "; ". */
    private static final String PART_SEPARATOR = "; ";
    /** The parts in words are set apart as the console sets words apart. */
    private static final String SEPARATOR = " · ";
    private static final String CUT = " …";

    // ----- the role scope (DecisionFactsResolver.roleScope)
    private static final Pattern ACTION = Pattern.compile(
            "^action (\\S+) (against|outside|within) the scope group's actions \\((.*)\\)$");
    private static final Pattern CATEGORY = Pattern.compile(
            "^category (\\S+) (against|outside|within) the scope group's categories \\((.*)\\)$");
    private static final Pattern PEERS = Pattern.compile("^scope group of ([0-9]+) other users?$");
    private static final String DENIED_ACTION = "action in the scope group's denied actions";
    private static final String DENIED_CATEGORY = "category in the scope group's denied categories";
    private static final String PROVISIONAL = "evidence PROVISIONAL";

    // ----- the comparison with the usual behaviour (Deviation.describe, DecisionFactsResolver.deviationFacts)
    private static final Map<String, String> LABELS = Map.of("time", "TIME", "day", "DAY", "network", "NETWORK",
            "device", "DEVICE", "login method", "LOGIN_METHOD", "target", "TARGET", "action", "ACTION",
            "class", "RESOURCE_CLASS", "size", "SIZE", "rate", "RATE");
    private static final String LABEL = "(time|day|network|device|login method|target|action|class|size|rate)";
    /** A value of the request: it holds none of the parts that follow it. */
    private static final String VALUE = "((?:(?! seen [0-9]| \\(|, usual ).)+)";
    private static final Pattern DEVIATION = Pattern.compile("^" + LABEL + "(?: " + VALUE + ")?"
            + "(?: \\(holds the usual (.+?)\\))?"
            + "(?: seen ([0-9]+) of ([0-9]+)(?: on ([0-9]+) of ([0-9]+) days)?"
            + "(?:, first (.+?), last (.+?)|, not in the window, last (.+?)|, (first time))?)?"
            + "(?:, usual (.+?))?"
            + "(?: \\((explained by .+|unexplained|baseline not established"
            + "|unknown: no usual behaviour to compare with)\\))?$");
    private static final Pattern COMPARED = Pattern.compile("^([0-9]+) of ([0-9]+) compared(?: -> (.+))?$");
    private static final String NOT_COMPARED = "not compared: ";
    private static final Pattern NOT_COMPARED_ITEM = Pattern.compile(LABEL + " \\(([^()]+)\\)");
    private static final Map<String, String> NOT_COMPARED_REASONS = Map.of(
            "no observations in the window", "noObservations", "the request does not state it", "notStated",
            "no observation holds it", "noneHolds", "no usual target of this kind", "noUsualTarget",
            "no export in the window", "noExport", "the request time is not known", "noTime",
            "no usual rate in the view", "noUsualRate");
    private static final Pattern CLOSEST = Pattern.compile(
            "^closest of the past records read for this action matches ([0-9]+) of ([0-9]+) on time, login method and"
                    + " browser$");
    private static final Pattern DATE = Pattern.compile(
            "^([0-9]{2}-[0-9]{2}) (Mon|Tue|Wed|Thu|Fri|Sat|Sun)(?: \\((.+)\\))?$");
    private static final Pattern WALL_CLOCK = Pattern.compile("^([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2})(?: \\((.+)\\))?$");
    private static final Pattern DISTANCE = Pattern.compile("^([0-9]+) (min|h|days) (before|after)$");
    private static final Pattern LIMIT = Pattern.compile("^the assigned limit of ([0-9,]+) items$");

    // ----- the session, the policy and the records (DecisionFactsResolver)
    private static final Pattern FIRST = Pattern.compile("^first (\\S+)( of this target)? in this session$");
    private static final Pattern NTH = Pattern.compile("^([0-9]+)(?:st|nd|rd|th) (\\S+) in this session"
            + "(?:, ([0-9]+) earlier of the same target(?:; ([0-9,]+) items exported to the same target before this"
            + " request)?)?$");
    private static final Pattern POLICY = Pattern.compile("^(.+?) requires (a covering approval"
            + "|a covering (?:([A-Z][A-Z0-9_]*) )?ticket|a covering record \\((.+?)\\))(?: \\(exceptions: (.+)\\))?$");
    private static final Pattern ASSIGNED_UP_TO = Pattern.compile("^assigned target up to ([0-9,]+) items$");
    private static final Pattern RECENT_WORK = Pattern.compile("^worked on the target in the last ([0-9]+) days$");
    private static final Pattern SATISFIED = Pattern.compile("^(yes|no|unknown)(?: — (.+))?$");
    private static final Pattern ON_CALL = Pattern.compile("^on call(?: \\((.+?)\\))?(?: until (.+))?$");
    private static final Pattern TRAVEL = Pattern.compile("^trip (?:(\\S+) )?to (.+?)(?:, network (\\S+))?"
            + "( holds the request address| does not hold the request address"
            + "|, whether it holds the request address is not known)$");
    private static final Pattern ASSIGNED = Pattern.compile("^(not )?assigned to (.+?)(?: \\((.+)\\))?$");
    private static final Pattern ACCOUNT_MANAGER = Pattern.compile("^(not the )?account manager of (.+)$");
    private static final Pattern WORKED = Pattern.compile(
            "^worked on (.+) on ([0-9]+) of the last (?:([0-9]+) days|days the host counts)$");
    private static final Pattern APPROVAL_HEAD = Pattern.compile("^(.+?)(?: by (.+))?$");
    private static final String CLAIMED = "the ticket named by the requester";
    private static final Pattern TICKET_HEAD = Pattern.compile("^(" + CLAIMED + "|\\S+)(?: ([A-Z][A-Z0-9_]*))?(?: by (.+))?$");
    private static final Pattern UP_TO = Pattern.compile("^up to ([0-9,]+) items$");
    private static final Pattern USED = Pattern.compile("^used ([0-9,]+) (in this session )?before this request$");
    private static final Pattern WINDOW = Pattern.compile("^(.*?)\\.\\.(.*?)(?: \\((.+)\\))?$");
    private static final Pattern SPAN = Pattern.compile("^from (.+?) to (.+) this request$");
    private static final Pattern FROM = Pattern.compile("^from (.+) this request$");
    private static final Pattern UNTIL = Pattern.compile("^until (.+) this request$");
    private static final Map<String, String> HOST_MARKS = Map.of(
            "its state is not an approved or active one", "STATUS", "it was approved by the requester", "APPROVER",
            "its purpose does not cover this action", "PURPOSE", "it is for another target", "TARGET",
            "this request is outside its validity", "VALIDITY", "this request asks for more items than it allows",
            "ITEMS");
    private static final String OUTSIDE_SESSION =
            "the items exported under it outside this session (the host does not report them)";
    private static final Pattern ITEM_COUNT = Pattern.compile(
            "^the request's item count against its limit of ([0-9,]+) \\(the request does not state it\\)$");
    private static final List<String> RECORD_PARTS = List.of("up to ", "used ", "valid ", "decided ",
            "decision time not recorded", "pending ", "break-glass", "the host marks: ",
            "the host's own check marks no mismatch with this request", "not known: ");
    /** The parts of a record line that hold a list, its items joined by ", " as the line's parts are. */
    private static final List<String> RECORD_LISTS = List.of("pending ", "the host marks: ", "not known: ");

    // ----- the cohort, the move, the session's client and the argument's origin
    private static final Pattern COHORT = Pattern.compile("^cohort (.+?): (.*)$");
    private static final Pattern COHORT_AGAINST = Pattern.compile(
            "^action (\\S+) against the cohort's usual actions \\((.*)\\)$");
    private static final Pattern COHORT_ACTION = Pattern.compile("^action (\\S+) (within|outside) the cohort's usual actions$");
    private static final Pattern COHORT_RESOURCE = Pattern.compile(
            "^resource (?:in the cohort's usual resources: (yes|no)|(within|outside) the cohort's usual resources)$");
    private static final Pattern MOVE = Pattern.compile(
            "^(.+) -> (.+?) ([0-9.]+ km|an unknown distance) in ([0-9]+ min|an unknown time)$");
    private static final Pattern CONFIDENCE = Pattern.compile("^location baseline confidence (.+)$");
    private static final Pattern CHANGE = Pattern.compile("^(.+) -> (.+) in the same session$");
    private static final Pattern ZONED = Pattern.compile("^(.+) \\(([A-Z][A-Z0-9_]*)\\)$");
    private static final Pattern ORIGIN = Pattern.compile("^(.+?) is not named in the user's request or in the company's"
            + " records; it first appeared in (?:the output of (.+?)|an earlier tool output)(?:, in the text: (.+))?$");
    private static final Pattern CONFLICT = Pattern.compile("^(.+?)(?: \\((.+)\\))?$");

    /** A code as the engine writes it ({@code EXPORT}, {@code PASSWORD+ONE_TIME_CODE}), set apart from other text. */
    private static final Pattern ENGINE_WORD = Pattern.compile(
            "(?<![\\w./@#:+-])[A-Z][A-Z0-9_]*(?:\\+[A-Z][A-Z0-9_]*)*(?![\\w./@#:+-])");
    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]*$");

    private final MessageSource messages;
    private final Locale locale;
    private final ZeroTrustDeviationWords values;

    ZeroTrustFactWords(MessageSource messages, Locale locale) {
        this.messages = messages;
        this.locale = locale == null ? Locale.ENGLISH : locale;
        this.values = new ZeroTrustDeviationWords(messages, this.locale);
    }

    /** The fact's value in words; null for none. */
    String words(String factName, String value) {
        if (value == null || value.isBlank() || factName == null) {
            return value;
        }
        // The summary keeps a value's first KEPT_LENGTH characters: a value of exactly that length was cut there.
        boolean cut = value.length() == KEPT_LENGTH;
        return switch (factName) {
            case DecisionFactsResolver.ROLE_SCOPE -> parts(value, PART_SEPARATOR, cut, this::roleScopePart);
            case DecisionFactsResolver.DEVIATIONS_FROM_BASELINE -> deviations(value, cut);
            case DecisionFactsResolver.SAME_AS_BASELINE -> "none".equals(value) ? message(F + "same.none", value)
                    : parts(value, PART_SEPARATOR, cut, this::deviation);
            case DecisionFactsResolver.REPEAT_IN_SESSION -> whole(value, cut, this::repeat);
            case DecisionFactsResolver.POLICY -> policies(value, cut);
            case DecisionFactsResolver.POLICY_SATISFIED -> whole(value, cut, this::satisfied);
            case DecisionFactsResolver.APPROVAL -> parts(value, PART_SEPARATOR, cut, line -> record(line, false));
            case DecisionFactsResolver.TICKET -> parts(value, PART_SEPARATOR, cut, line -> record(line, true));
            case DecisionFactsResolver.ASSIGNMENT -> parts(value, PART_SEPARATOR, cut, this::assignment);
            case DecisionFactsResolver.ON_CALL -> whole(value, cut, this::onCall);
            case DecisionFactsResolver.TRAVEL -> whole(value, cut, this::travel);
            case DecisionFactsResolver.DATA_CONFLICTS -> parts(value, PART_SEPARATOR, cut, this::conflict);
            case DecisionFactsResolver.PEER_COHORT -> cohort(value, cut);
            case DecisionFactsResolver.MOVEMENT -> parts(value, PART_SEPARATOR, cut, this::movement);
            case DecisionFactsResolver.SESSION_DEVICE_CHANGE -> whole(value, cut, change -> sessionChange(change, true));
            case DecisionFactsResolver.SESSION_NETWORK_CHANGE -> whole(value, cut, change -> sessionChange(change, false));
            case DecisionFactsResolver.ARGUMENT_ORIGIN -> parts(value, " | ", cut, this::origin);
            default -> cut ? codes(value) + CUT : codes(value);
        };
    }

    // ----- parts and the value cut short

    /** Each part of the value in words; the last part of a value cut short as far as it reads. */
    private String parts(String value, String separator, boolean cut, Function<String, String> part) {
        String[] pieces = value.split(Pattern.quote(separator), -1);
        List<String> words = new ArrayList<>();
        for (int i = 0; i < pieces.length; i++) {
            String piece = pieces[i].trim();
            if (!piece.isEmpty()) {
                words.add(cut && i == pieces.length - 1 ? shortened(piece, part) : read(part, piece));
            }
        }
        return String.join(SEPARATOR, words);
    }

    private String whole(String value, boolean cut, Function<String, String> reading) {
        return cut ? shortened(value.trim(), reading) : read(reading, value.trim());
    }

    /** A part this reads in words, else its text with its engine words in words. */
    private String read(Function<String, String> reading, String part) {
        String words = reading.apply(part);
        return words != null ? words : codes(part);
    }

    /** A part the summary cut: its words up to the last word it still reads, then an ellipsis. */
    private String shortened(String part, Function<String, String> reading) {
        String rest = part;
        while (!rest.isEmpty()) {
            String words = reading.apply(rest);
            if (words != null) {
                return words + CUT;
            }
            int space = rest.lastIndexOf(' ');
            if (space <= 0) {
                break;
            }
            rest = rest.substring(0, space).replaceAll("[,;:(]+$", "").trim();
        }
        return codes(part) + CUT;
    }

    // ----- the role scope

    private String roleScopePart(String part) {
        Matcher action = ACTION.matcher(part);
        if (action.matches()) {
            return message(RS + "action." + action.group(2), part, action(action.group(1)), list(action.group(3), true));
        }
        Matcher category = CATEGORY.matcher(part);
        if (category.matches()) {
            return message(RS + "category." + category.group(2), part, category(category.group(1)),
                    list(category.group(3), false));
        }
        Matcher peers = PEERS.matcher(part);
        if (peers.matches()) {
            long count = Long.parseLong(peers.group(1));
            return message(RS + (count == 1 ? "peer" : "peers"), part, count);
        }
        return switch (part) {
            case DENIED_ACTION -> message(RS + "deniedAction", part);
            case DENIED_CATEGORY -> message(RS + "deniedCategory", part);
            case PROVISIONAL -> message(RS + "provisional", part);
            default -> null;
        };
    }

    private String list(String values, boolean actions) {
        List<String> words = new ArrayList<>();
        for (String value : values.split(",")) {
            if (!value.isBlank()) {
                words.add(actions ? action(value.trim()) : category(value.trim()));
            }
        }
        return String.join(", ", words);
    }

    // ----- the comparison with the usual behaviour

    /** {@code 4 of 7 compared -> part; part; not compared: ...; closest of the past records ...}. */
    private String deviations(String value, boolean cut) {
        String[] pieces = value.split(PART_SEPARATOR, -1);
        Matcher head = COMPARED.matcher(pieces[0].trim());
        boolean headCut = cut && pieces.length == 1;
        if (!head.matches()) {
            return parts(value, PART_SEPARATOR, cut, this::comparisonPart);
        }
        List<String> different = new ArrayList<>();
        if (head.group(3) != null) {
            different.add(headCut ? shortened(head.group(3), this::deviation) : read(this::deviation, head.group(3)));
        }
        List<String> others = new ArrayList<>();
        for (int i = 1; i < pieces.length; i++) {
            String piece = pieces[i].trim();
            boolean last = cut && i == pieces.length - 1;
            if (piece.isEmpty()) {
                continue;
            }
            if (piece.startsWith(NOT_COMPARED) || piece.startsWith("closest ")) {
                others.add(last ? shortened(piece, this::comparisonPart) : read(this::comparisonPart, piece));
            } else {
                different.add(last ? shortened(piece, this::deviation) : read(this::deviation, piece));
            }
        }
        String text = message(F + "deviations.head", pieces[0], head.group(1), head.group(2));
        if (!different.isEmpty()) {
            text = message(F + "deviations.different", text, text, String.join(SEPARATOR, different));
        }
        List<String> all = new ArrayList<>(List.of(text));
        all.addAll(others);
        return String.join(SEPARATOR, all) + (headCut && head.group(3) == null ? CUT : "");
    }

    /** A part of the comparison beside the differences: what was not compared, and the closest past record. */
    private String comparisonPart(String part) {
        if (part.startsWith(NOT_COMPARED)) {
            Matcher item = NOT_COMPARED_ITEM.matcher(part.substring(NOT_COMPARED.length()));
            List<String> items = new ArrayList<>();
            while (item.find()) {
                String reason = NOT_COMPARED_REASONS.get(item.group(2));
                items.add(message(F + "deviations.notComparedItem", item.group(), dimension(item.group(1)),
                        reason != null ? message(F + "notCompared." + reason, item.group(2)) : codes(item.group(2))));
            }
            return items.isEmpty() ? null : message(F + "deviations.notCompared", part, String.join(", ", items));
        }
        Matcher closest = CLOSEST.matcher(part);
        return closest.matches() ? message(F + "deviations.closest", part, closest.group(1), closest.group(2)) : null;
    }

    /** One comparison: {@code network 203.0.113.0/24 seen 0 of 1 on 0 of 1 days, first time (...)}. */
    private String deviation(String part) {
        Matcher m = DEVIATION.matcher(part);
        if (!m.matches()) {
            return null;
        }
        String dimension = LABELS.get(m.group(1));
        String named = message(DIMENSION + dimension, m.group(1));
        String value = m.group(2) != null ? message(F + "deviation.value", part, named, current(dimension,
                m.group(2).trim())) : named;
        List<String> details = new ArrayList<>();
        if (m.group(3) != null) {
            details.add(message(F + "deviation.holds", part, values.current(dimension, m.group(3))));
        }
        if (m.group(4) != null) {
            details.add(message(F + "deviation.seen", part, m.group(4), m.group(5)));
        }
        if (m.group(6) != null) {
            details.add(message(F + "deviation.days", part, m.group(6), m.group(7)));
        }
        if (m.group(8) != null) {
            details.add(message(F + "deviation.firstLast", part, date(m.group(8)), date(m.group(9))));
        } else if (m.group(10) != null) {
            details.add(message(F + "deviation.notInWindow", part, date(m.group(10))));
        } else if (m.group(11) != null) {
            details.add(message(F + "deviation.firstTime", part));
        }
        if (m.group(12) != null) {
            details.add(message(F + "deviation.usual", part, values.usualWritten(dimension, m.group(12))));
        }
        if (m.group(13) != null) {
            details.add(explanation(m.group(13)));
        }
        return details.isEmpty() ? value : message(F + "deviation.detail", part, value, String.join(", ", details));
    }

    /** The request's value of a comparison; a target by the names of its variables ({@code projectKey,} as projectKey). */
    private String current(String dimension, String value) {
        if ("TARGET".equals(dimension)) {
            List<String> names = new ArrayList<>();
            for (String name : value.split(",")) {
                if (!name.isBlank()) {
                    names.add(name.trim());
                }
            }
            return names.isEmpty() ? value : String.join(", ", names);
        }
        return values.current(dimension, value);
    }

    private String explanation(String explanation) {
        return switch (explanation) {
            case "unexplained" -> message(F + "deviation.unexplained", explanation);
            case "baseline not established" -> message(F + "deviation.notEstablished", explanation);
            case "unknown: no usual behaviour to compare with" -> message(F + "deviation.noUsual", explanation);
            default -> message(F + "deviation.explained", explanation,
                    explainer(explanation.substring("explained by ".length())));
        };
    }

    /** What explains a difference (v20 notation): a record, the assigned item limit or a trip. */
    private String explainer(String by) {
        Matcher limit = LIMIT.matcher(by);
        if (limit.matches()) {
            return message(F + "explainer.limit", by, limit.group(1));
        }
        if ("trip registered by the host".equals(by)) {
            return message(F + "explainer.tripHost", by);
        }
        return by.startsWith("trip ") ? message(F + "explainer.trip", by, by.substring(5)) : by;
    }

    private String dimension(String label) {
        return message(DIMENSION + LABELS.get(label), label);
    }

    /** {@code 11-18 Wed (19 min before this request)}. */
    private String date(String text) {
        Matcher m = DATE.matcher(text.trim());
        if (!m.matches()) {
            return codes(text);
        }
        String day = m.group(2);
        for (DayOfWeek week : DayOfWeek.values()) {
            if (week.getDisplayName(TextStyle.SHORT, Locale.ROOT).equals(m.group(2))) {
                day = week.getDisplayName(TextStyle.SHORT, locale);
            }
        }
        String date = message(F + "date", text, m.group(1), day);
        return m.group(3) != null ? message(F + "dated", text, date, relative(m.group(3))) : date;
    }

    /** {@code 11-18 09:30 (4 h before this request)}. */
    private String wallClock(String text) {
        Matcher m = WALL_CLOCK.matcher(text.trim());
        if (!m.matches()) {
            return codes(text);
        }
        return m.group(2) != null ? message(F + "dated", text, m.group(1), relative(m.group(2))) : m.group(1);
    }

    /** {@code 19 min before this request}. */
    private String relative(String text) {
        Matcher point = UNTIL.matcher("until " + text);
        return point.matches() ? message(F + "relative.point", text, distance(point.group(1))) : text;
    }

    /** {@code 3 h before}. */
    private String distance(String text) {
        Matcher m = DISTANCE.matcher(text.trim());
        if (!m.matches()) {
            return text;
        }
        String amount = message(F + "amount." + m.group(2), text, m.group(1));
        return message(F + ("before".equals(m.group(3)) ? "relative.ago" : "relative.later"), text, amount);
    }

    /** {@code 11-18 09:00..11-19 09:00 (from 3 h before to 21 h after this request)}. */
    private String window(String text) {
        Matcher m = WINDOW.matcher(text.trim());
        if (!m.matches()) {
            return codes(text);
        }
        String from = m.group(1).trim();
        String until = m.group(2).trim();
        String window = !from.isEmpty() && !until.isEmpty() ? message(F + "window.both", text, from, until)
                : !from.isEmpty() ? message(F + "window.from", text, from) : message(F + "window.until", text, until);
        if (m.group(3) == null) {
            return window;
        }
        String relative = m.group(3);
        Matcher span = SPAN.matcher(relative);
        Matcher since = FROM.matcher(relative);
        Matcher to = UNTIL.matcher(relative);
        String words = span.matches() ? message(F + "relative.span", relative, distance(span.group(1)),
                distance(span.group(2)))
                : since.matches() ? message(F + "relative.from", relative, distance(since.group(1)))
                : to.matches() ? message(F + "relative.until", relative, distance(to.group(1))) : relative;
        return message(F + "window.relative", text, window, words);
    }

    // ----- the session's repeats

    /** {@code first READ of this target in this session}, {@code 5th EXPORT in this session, 2 earlier ...}. */
    private String repeat(String value) {
        Matcher first = FIRST.matcher(value);
        if (first.matches()) {
            return message(F + (first.group(2) != null ? "repeat.firstOfTarget" : "repeat.first"), value,
                    what(first.group(1)));
        }
        Matcher nth = NTH.matcher(value);
        if (!nth.matches()) {
            return null;
        }
        String text = message(F + "repeat.nth", value, nth.group(1), what(nth.group(2)),
                nth.group(1) + ordinalSuffix(Integer.parseInt(nth.group(1))));
        if (nth.group(3) != null) {
            text = text + ", " + message(F + "repeat.sameTarget", value, nth.group(3));
        }
        if (nth.group(4) != null) {
            text = text + ", " + message(F + "repeat.exported", value, nth.group(4));
        }
        return text;
    }

    private String what(String action) {
        return "request".equals(action) ? message(F + "repeat.request", action) : action(action);
    }

    private static String ordinalSuffix(int value) {
        int lastTwo = value % 100;
        return lastTwo >= 11 && lastTwo <= 13 ? "th" : switch (value % 10) {
            case 1 -> "st";
            case 2 -> "nd";
            case 3 -> "rd";
            default -> "th";
        };
    }

    // ----- the company's policy

    /** Policies joined by "; " outside the parentheses of their exceptions. */
    private String policies(String value, boolean cut) {
        List<String> pieces = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            depth += c == '(' ? 1 : c == ')' ? -1 : 0;
            if (depth == 0 && value.startsWith(PART_SEPARATOR, i)) {
                pieces.add(value.substring(start, i));
                start = i + PART_SEPARATOR.length();
            }
        }
        pieces.add(value.substring(start));
        List<String> words = new ArrayList<>();
        for (int i = 0; i < pieces.size(); i++) {
            String piece = pieces.get(i).trim();
            words.add(cut && i == pieces.size() - 1 ? shortened(piece, this::policy) : read(this::policy, piece));
        }
        return String.join(SEPARATOR, words);
    }

    private String policy(String part) {
        Matcher m = POLICY.matcher(part);
        if (!m.matches()) {
            return null;
        }
        String id = "company policy".equals(m.group(1)) ? message(F + "policy.company", m.group(1)) : m.group(1);
        String needs = m.group(2).equals("a covering approval") ? message(F + "policy.needs.approval", m.group(2))
                : m.group(4) != null ? message(F + "policy.needs.record", m.group(2), "not stated".equals(m.group(4))
                ? message(F + "policy.notStated", m.group(4)) : word(STATUS_WORD, m.group(4)))
                : m.group(3) != null ? message(F + "policy.needs.kindTicket", m.group(2), word(TICKET_KIND_WORD,
                m.group(3))) : message(F + "policy.needs.ticket", m.group(2));
        String text = message(F + "policy.requires", part, id, needs);
        if (m.group(5) == null) {
            return text;
        }
        List<String> exceptions = new ArrayList<>();
        for (String exception : m.group(5).split(PART_SEPARATOR)) {
            exceptions.add(exception(exception.trim()));
        }
        return message(F + "policy.exceptions", part, text, String.join(", ", exceptions));
    }

    private String exception(String exception) {
        Matcher upTo = ASSIGNED_UP_TO.matcher(exception);
        if (upTo.matches()) {
            return message(F + "policy.exception.assignedUpTo", exception, upTo.group(1));
        }
        Matcher recent = RECENT_WORK.matcher(exception);
        if (recent.matches()) {
            return message(F + "policy.exception.recentWork", exception, recent.group(1));
        }
        return switch (exception) {
            case "assigned target" -> message(F + "policy.exception.assigned", exception);
            case "account manager" -> message(F + "policy.exception.accountManager", exception);
            case "worked on the target in the last days the host sets" ->
                    message(F + "policy.exception.recentWorkHost", exception);
            case "ticket while on call" -> message(F + "policy.exception.ticketOnCall", exception);
            default -> exception;
        };
    }

    /** {@code yes — ...} (v20 notation): whether the policy is met, with the engine's detail. */
    private String satisfied(String value) {
        Matcher m = SATISFIED.matcher(value);
        if (!m.matches()) {
            return null;
        }
        String answer = message(F + "satisfied." + m.group(1), m.group(1));
        return m.group(2) != null ? message(F + "satisfied.detail", value, answer, codes(m.group(2))) : answer;
    }

    // ----- the approval and ticket records

    /**
     * An approval or ticket line: its id and approver, the host's values (state, purpose, target) and the parts the
     * engine writes (limit, use, validity, decision time, pending approvers, break-glass, the host's marks, what is not
     * known); in the v20 notation, whether it covers this request after a dash.
     */
    private String record(String line, boolean ticket) {
        if (ticket && "no ticket found".equals(line)) {
            return message(F + "ticket.none", line);
        }
        if (ticket && (CLAIMED + " does not exist").equals(line)) {
            return message(F + "ticket.claimFalse", line);
        }
        int dash = line.indexOf(" — ");
        String body = dash >= 0 ? line.substring(0, dash) : line;
        List<String> tokens = new ArrayList<>(List.of(body.split(", ")));
        List<String> words = new ArrayList<>();
        String head = tokens.remove(0);
        if (ticket) {
            Matcher m = TICKET_HEAD.matcher(head);
            if (!m.matches()) {
                return null;
            }
            words.add(CLAIMED.equals(m.group(1)) ? message(F + "ticket.claimed", m.group(1)) : m.group(1));
            if (m.group(2) != null) {
                words.add(message(F + "ticket.kind", m.group(2), word(TICKET_KIND_WORD, m.group(2))));
            }
            if (m.group(3) != null) {
                words.add(message(F + "record.by", m.group(3), m.group(3)));
            }
        } else {
            Matcher m = APPROVAL_HEAD.matcher(head);
            if (!m.matches()) {
                return null;
            }
            words.add(m.group(1));
            if (m.group(2) != null) {
                words.add(message(F + "record.by", m.group(2), m.group(2)));
            }
        }
        // The pieces of a part a list makes ("pending a, b", "not known: x, y") join it again.
        List<String> pieces = new ArrayList<>();
        for (String token : tokens) {
            String previous = pieces.isEmpty() ? null : pieces.get(pieces.size() - 1);
            if (previous != null && RECORD_LISTS.stream().anyMatch(previous::startsWith)
                    && RECORD_PARTS.stream().noneMatch(token::startsWith)) {
                pieces.set(pieces.size() - 1, previous + ", " + token);
            } else {
                pieces.add(token);
            }
        }
        for (String piece : pieces) {
            words.add(recordPart(piece));
        }
        String text = String.join(SEPARATOR, words);
        return dash >= 0 ? message(F + "record.verdict", line, text, verdict(line.substring(dash + 3))) : text;
    }

    private String recordPart(String piece) {
        Matcher upTo = UP_TO.matcher(piece);
        if (upTo.matches()) {
            return message(F + "record.upTo", piece, upTo.group(1));
        }
        Matcher used = USED.matcher(piece);
        if (used.matches()) {
            return message(F + (used.group(2) != null ? "record.usedInSession" : "record.used"), piece, used.group(1));
        }
        if (piece.startsWith("valid ")) {
            return message(F + "record.valid", piece, window(piece.substring(6)));
        }
        if (piece.startsWith("decided ")) {
            return message(F + "record.decided", piece, wallClock(piece.substring(8)));
        }
        if (piece.startsWith("decision time not recorded")) {
            return message(F + "record.notDecided", piece);
        }
        if (piece.startsWith("pending ")) {
            return message(F + "record.pending", piece, piece.substring(8));
        }
        if ("break-glass".equals(piece)) {
            return message(F + "record.breakGlass", piece);
        }
        if (piece.startsWith("the host marks: ")) {
            List<String> marks = new ArrayList<>();
            for (String mark : piece.substring(16).split(", ")) {
                String code = HOST_MARKS.get(mark.trim());
                marks.add(code != null ? message(F + "record.mark." + code, mark) : codes(mark));
            }
            return message(F + "record.hostMarks", piece, String.join(", ", marks));
        }
        if (piece.startsWith("the host's own check marks no mismatch")) {
            return message(F + "record.hostNoMismatch", piece);
        }
        if (piece.startsWith("not known: ")) {
            List<String> unknowns = new ArrayList<>();
            for (String unknown : piece.substring(11).split(", (?=the )")) {
                Matcher count = ITEM_COUNT.matcher(unknown.trim());
                unknowns.add(OUTSIDE_SESSION.equals(unknown.trim()) ? message(F + "record.unknown.outside", unknown)
                        : count.matches() ? message(F + "record.unknown.count", unknown, count.group(1)) : codes(unknown));
            }
            return message(F + "record.notKnown", piece, String.join(", ", unknowns));
        }
        // A value of the host's record: its state, purpose or target; a state code by its word.
        return CODE.matcher(piece).matches() ? word(STATUS_WORD, piece) : piece;
    }

    /** Whether the record covers this request (v20 notation). */
    private String verdict(String verdict) {
        if ("covers this request".equals(verdict)) {
            return message(F + "record.covers", verdict);
        }
        if (verdict.startsWith("does not cover: ")) {
            return message(F + "record.notCovers", verdict, codes(verdict.substring(16)));
        }
        if (verdict.startsWith("not known whether it covers: ")) {
            return message(F + "record.undecided", verdict, codes(verdict.substring(29)));
        }
        return codes(verdict);
    }

    private String assignment(String part) {
        Matcher assigned = ASSIGNED.matcher(part);
        if (assigned.matches()) {
            String text = message(F + (assigned.group(1) != null ? "assignment.notAssigned" : "assignment.assigned"),
                    part, target(assigned.group(2)));
            return assigned.group(3) != null ? message(F + "assignment.responsibility", part, text, assigned.group(3))
                    : text;
        }
        Matcher manager = ACCOUNT_MANAGER.matcher(part);
        if (manager.matches()) {
            return message(F + (manager.group(1) != null ? "assignment.notAccountManager" : "assignment.accountManager"),
                    part, target(manager.group(2)));
        }
        Matcher worked = WORKED.matcher(part);
        if (worked.matches()) {
            return worked.group(3) != null
                    ? message(F + "assignment.worked", part, target(worked.group(1)), worked.group(2), worked.group(3))
                    : message(F + "assignment.workedHost", part, target(worked.group(1)), worked.group(2));
        }
        return null;
    }

    private String target(String target) {
        return "this target".equals(target) ? message(F + "target.this", target) : target;
    }

    private String onCall(String value) {
        if ("not on call".equals(value)) {
            return message(F + "onCall.off", value);
        }
        Matcher m = ON_CALL.matcher(value);
        if (!m.matches()) {
            return null;
        }
        String text = message(F + "onCall.on", value);
        if (m.group(1) != null) {
            text = message(F + "onCall.team", value, text, m.group(1));
        }
        return m.group(2) != null ? message(F + "onCall.until", value, text, wallClock(m.group(2))) : text;
    }

    private String travel(String value) {
        if ("no registered trip holds the request address".equals(value)) {
            return message(F + "travel.none", value);
        }
        Matcher m = TRAVEL.matcher(value);
        if (!m.matches()) {
            return null;
        }
        String place = "an unnamed place".equals(m.group(2)) ? message(F + "travel.unnamed", m.group(2)) : m.group(2);
        String trip = m.group(1) != null ? message(F + "travel.plan", value, m.group(1), place)
                : message(F + "travel.noPlan", value, place);
        if (m.group(3) != null) {
            trip = message(F + "travel.network", value, trip, m.group(3));
        }
        String holds = m.group(4).startsWith(" holds") ? "travel.holds"
                : m.group(4).startsWith(" does not") ? "travel.notHolds" : "travel.unknown";
        return message(F + holds, value, trip);
    }

    private String conflict(String part) {
        Matcher m = CONFLICT.matcher(part);
        if (!m.matches()) {
            return null;
        }
        return m.group(2) != null ? message(F + "conflict.sources", part, m.group(1), m.group(2))
                : message(F + "conflict.field", part, m.group(1));
    }

    // ----- the cohort, the move, the session's client and the argument's origin

    private String cohort(String value, boolean cut) {
        Matcher named = COHORT.matcher(value);
        String parts = parts(named.matches() ? named.group(2) : value, PART_SEPARATOR, cut, this::cohortPart);
        return named.matches() ? message(F + "cohort.named", value, named.group(1), parts) : parts;
    }

    private String cohortPart(String part) {
        Matcher against = COHORT_AGAINST.matcher(part);
        if (against.matches()) {
            return message(F + "cohort.action.against", part, action(against.group(1)), list(against.group(2), true));
        }
        Matcher action = COHORT_ACTION.matcher(part);
        if (action.matches()) {
            return message(F + "cohort.action." + action.group(2), part, action(action.group(1)));
        }
        Matcher resource = COHORT_RESOURCE.matcher(part);
        if (resource.matches()) {
            boolean usual = "yes".equals(resource.group(1)) || "within".equals(resource.group(2));
            return message(F + (usual ? "cohort.resource.within" : "cohort.resource.outside"), part);
        }
        return switch (part) {
            case "an outlier against the cohort" -> message(F + "cohort.outlier", part);
            case "not an outlier against the cohort" -> message(F + "cohort.notOutlier", part);
            default -> null;
        };
    }

    private String movement(String part) {
        Matcher move = MOVE.matcher(part);
        if (move.matches()) {
            String from = "an unknown previous location".equals(move.group(1))
                    ? message(F + "movement.unknownFrom", move.group(1)) : move.group(1);
            String to = "an unknown current location".equals(move.group(2))
                    ? message(F + "movement.unknownTo", move.group(2)) : move.group(2);
            String distance = move.group(3).endsWith(" km")
                    ? message(F + "movement.km", move.group(3), move.group(3).substring(0, move.group(3).length() - 3))
                    : message(F + "movement.unknownDistance", move.group(3));
            String elapsed = move.group(4).endsWith(" min")
                    ? message(F + "amount.min", move.group(4), move.group(4).substring(0, move.group(4).length() - 4))
                    : message(F + "movement.unknownTime", move.group(4));
            return message(F + "movement.move", part, from, to, distance, elapsed);
        }
        Matcher confidence = CONFIDENCE.matcher(part);
        if (confidence.matches()) {
            return message(F + "movement.confidence", part, codes(confidence.group(1)));
        }
        return switch (part) {
            case "the host states an impossible travel" -> message(F + "movement.impossible", part);
            case "the host states no impossible travel" -> message(F + "movement.possible", part);
            default -> null;
        };
    }

    private String sessionChange(String value, boolean device) {
        Matcher m = CHANGE.matcher(value);
        if (!m.matches()) {
            return null;
        }
        return message(F + "session.change", value, device ? client(m.group(1)) : network(m.group(1)),
                device ? client(m.group(2)) : network(m.group(2)));
    }

    /** A network of the session with its zone: {@code 10.40.12.0/24 (CORPORATE)} with the zone's word. */
    private String network(String network) {
        Matcher m = ZONED.matcher(network);
        return m.matches() ? message(F + "session.zoned", network, m.group(1), word(ZONE_WORD, m.group(2))) : network;
    }

    /** A client of the session: {@code Chrome/140 on WINDOWS} as the comparison reads a device. */
    private String client(String client) {
        return "a client that names no browser or operating system".equals(client)
                ? message(F + "session.noClient", client) : values.current("DEVICE", client);
    }

    private String origin(String clause) {
        Matcher m = ORIGIN.matcher(clause);
        if (!m.matches()) {
            return null;
        }
        String where = m.group(2) != null ? message(F + "origin.tool", clause, m.group(2))
                : message(F + "origin.earlier", clause);
        String text = message(F + "origin.value", clause, m.group(1), where);
        return m.group(3) != null ? message(F + "origin.excerpt", clause, text, m.group(3)) : text;
    }

    // ----- codes

    /** The text with the engine's codes in words: an action, a resource class, an operating system or a login. */
    private String codes(String text) {
        if (text == null) {
            return null;
        }
        Matcher m = ENGINE_WORD.matcher(text);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(out, Matcher.quoteReplacement(codeWord(m.group())));
        }
        m.appendTail(out);
        return out.toString();
    }

    private String codeWord(String code) {
        if (code.contains("+")) {
            List<String> methods = new ArrayList<>();
            for (String method : code.split("\\+")) {
                String word = known(LOGIN_WORD, method);
                if (word == null) {
                    return code;
                }
                methods.add(word);
            }
            return String.join(" + ", methods);
        }
        for (String prefix : List.of(ACTION_WORD, CLASS_WORD, OS_WORD, LOGIN_WORD, STATUS_WORD, ZONE_WORD)) {
            String word = known(prefix, code);
            if (word != null) {
                return word;
            }
        }
        // A code no dictionary names is read in words when it is plainly one (two words or more).
        return code.contains("_") ? code.toLowerCase(Locale.ROOT).replace('_', ' ') : code;
    }

    private String action(String code) {
        return word(ACTION_WORD, code);
    }

    private String category(String code) {
        return word(CATEGORY_WORD, code);
    }

    /**
     * A code by the word a message gives it, else in words: {@code CUSTOMER_RECORDS} reads as customer records. A code
     * of the host (a business category, a record state, a ticket kind) has no word of the product's for every value.
     */
    private String word(String prefix, String code) {
        String word = known(prefix, code);
        if (word != null) {
            return word;
        }
        return CODE.matcher(code).matches() ? code.toLowerCase(Locale.ROOT).replace('_', ' ') : code;
    }

    private String known(String prefix, String code) {
        if (messages == null) {
            return null;
        }
        String word = messages.getMessage(prefix + code.toUpperCase(Locale.ROOT), null, "", locale);
        return word == null || word.isEmpty() ? null : word;
    }

    private String message(String key, String fallback, Object... args) {
        return messages == null ? fallback : messages.getMessage(key, args, fallback, locale);
    }
}
