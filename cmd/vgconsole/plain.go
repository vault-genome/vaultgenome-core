// Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vault-genome/vaultgenome-core/internal/console"
	"github.com/vault-genome/vaultgenome-core/internal/contracts/audit_event"
	"github.com/vault-genome/vaultgenome-core/internal/shared/tee"
	"github.com/vault-genome/vaultgenome-core/internal/vault/trust"
)

// Everything a person reads on the page is written here, in plain words: no
// measurement, no gate, no attestation. A word of it that a bank clerk would
// have to ask about is a bug.

func tr(lang, ru, en string) string {
	if lang == "ru" {
		return ru
	}
	return en
}

// Tones of a line on the page. limit is what the platform cannot prove: it is
// shown and it does not count against the server.
const (
	toneOK    = "ok"
	toneWarn  = "warn"
	toneBad   = "bad"
	toneLimit = "limit"
	toneInfo  = "info"
)

// CheckLine is one statement of what was checked.
type CheckLine struct {
	Tone  string `json:"tone"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

// JournalLine is one record of the journal in plain words.
type JournalLine struct {
	Index   int       `json:"index"`
	At      time.Time `json:"at"`
	Tone    string    `json:"tone"`
	Text    string    `json:"text"`
	Minor   bool      `json:"minor"`
	Request string    `json:"request,omitempty"`
}

// PersonLine is one person who has access.
type PersonLine struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	PublicKeyHex string `json:"public_key_hex"`
	HoldsStop    bool   `json:"holds_stop"`
	You          bool   `json:"you"`
}

// RestoreLine is the last restore check, read from the journal.
type RestoreLine struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Seconds float64   `json:"seconds"`
	Level   string    `json:"level,omitempty"`
	Matched int       `json:"matched,omitempty"`
	// Stopped says the emergency stop refused it, which is not a failure.
	Stopped bool `json:"stopped,omitempty"`
}

// Overview is the whole page's content.
type Overview struct {
	ServerID    string        `json:"server_id"`
	ServerLabel string        `json:"server_label"`
	Where       string        `json:"where"`
	Version     string        `json:"version"`
	Verdict     string        `json:"verdict"`
	Headline    string        `json:"headline"`
	Subline     string        `json:"subline"`
	CheckedAt   *time.Time    `json:"checked_at,omitempty"`
	Lines       []CheckLine   `json:"lines"`
	Journal     []JournalLine `json:"journal"`
	JournalAll  int           `json:"journal_all"`
	People      []PersonLine  `json:"people"`
	You         string        `json:"you"`
	YourRole    string        `json:"your_role"`
	CanRestore  bool          `json:"can_restore"`
	CanStop     bool          `json:"can_stop"`
	CanInvite   bool          `json:"can_invite"`
	Stopped     bool          `json:"stopped"`
	StopReason  string        `json:"stop_reason,omitempty"`
	CanMove     bool          `json:"can_move"`
	Targets     []TargetLine  `json:"targets"`
	AllServers  []TargetLine  `json:"all_servers"`
}

// TargetLine is another server this person holds a pass for.
type TargetLine struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// otherServers are the servers this person may move a model to: those where
// they have full access.
func (a *App) otherServers(s *server) []*server {
	var out []*server
	for _, other := range a.Servers() {
		if other.id != s.id && other.you.Role == console.RoleOwner {
			out = append(out, other)
		}
	}
	return out
}

func roleText(lang string, r console.Role) string {
	switch r {
	case console.RolePeer:
		return tr(lang, "сервер, только на время переноса", "a server, for the time of a move only")
	case console.RoleOwner:
		return tr(lang, "полный доступ", "full access")
	case console.RoleOperator:
		return tr(lang, "просмотр и проверки", "view and run checks")
	default:
		return tr(lang, "только просмотр", "view only")
	}
}

// chipMaker names who signed for the family.
func chipMaker(p tee.Provider) string {
	switch p {
	case tee.ProviderGCPTDX:
		return "Intel"
	case tee.ProviderSimulated:
		return "(simulated)"
	default:
		return "AMD"
	}
}

func whereText(lang string, p tee.Provider) string {
	switch p {
	case tee.ProviderAWSSEVSNP:
		return tr(lang, "Amazon Web Services, защищённый сервер AMD", "Amazon Web Services, AMD confidential server")
	case tee.ProviderGCPSEVSNP, tee.ProviderGCPSEVSNPVTPM:
		return tr(lang, "Google Cloud, защищённый сервер AMD", "Google Cloud, AMD confidential server")
	case tee.ProviderGCPTDX:
		return tr(lang, "Google Cloud, защищённый сервер Intel", "Google Cloud, Intel confidential server")
	case tee.ProviderAzureSEVSNP:
		return tr(lang, "Microsoft Azure, защищённый сервер AMD", "Microsoft Azure, AMD confidential server")
	case tee.ProviderSimulated:
		return tr(lang, "Учебный режим: настоящего чипа нет", "Training mode: no real chip")
	}
	return string(p)
}

// overview puts together what the page shows, from what was verified here.
func (a *App) overview(s *server, lang string) Overview {
	s.mu.Lock()
	last, lastErr, unproven, journalErr := s.last, s.lastErr, s.unproven, s.journalErr
	events, first := s.events, s.first
	s.mu.Unlock()

	o := Overview{ServerID: s.id, ServerLabel: s.pass.ServerLabel, Where: whereText(lang, s.provider),
		You: s.you.Name, YourRole: roleText(lang, s.you.Role), Lines: []CheckLine{}, Journal: []JournalLine{}, People: []PersonLine{},
		CanRestore: s.you.Role.CanRestore(), CanInvite: s.you.Role.CanAdminister(), Targets: []TargetLine{}, AllServers: []TargetLine{}}
	for _, other := range a.Servers() {
		o.AllServers = append(o.AllServers, TargetLine{ID: other.id, Label: other.pass.ServerLabel})
	}
	if last != nil {
		at := last.At
		o.CheckedAt = &at
		o.Version = last.State.Version
	}
	for i := range events {
		if line, ok := describe(events[i], first+i, lang); ok {
			o.Journal = append(o.Journal, line)
		}
	}
	// Newest first on the page.
	for i, j := 0, len(o.Journal)-1; i < j; i, j = i+1, j-1 {
		o.Journal[i], o.Journal[j] = o.Journal[j], o.Journal[i]
	}
	o.JournalAll = len(events)

	switch {
	case unproven != nil:
		o.Verdict = "unproven"
		o.Headline = tr(lang, "Сервер не подтвердил себя", "The server did not prove itself")
		o.Subline = tr(lang, "Подпись чипа не сошлась. Не доверяйте этому серверу и сообщите в ИТ-отдел.", "The chip's signature did not check out. Do not trust this server and tell your IT department.")
		o.Lines = append(o.Lines, CheckLine{toneBad, tr(lang, "Подпись чипа не сошлась", "The chip's signature did not check out"), plainError(lang, unproven)})
		return o
	case lastErr != nil:
		o.Verdict = "offline"
		o.Headline = tr(lang, "Нет связи с сервером", "No connection to the server")
		o.Subline = tr(lang, "Сервер не ответил. Показано то, что было подтверждено в последний раз.", "The server did not answer. This is what was last proved.")
		o.Lines = append(o.Lines, CheckLine{toneBad, tr(lang, "Сервер не ответил", "The server did not answer"), plainError(lang, lastErr)})
	case last == nil:
		o.Verdict = "unknown"
		o.Headline = tr(lang, "Ещё не проверено", "Not checked yet")
		o.Subline = tr(lang, "Нажмите «Проверить сейчас».", "Press “Check now”.")
		return o
	}
	if last == nil {
		return o
	}

	st := last.State
	o.Lines = append(o.Lines, CheckLine{toneOK,
		tr(lang, "Сервер настоящий", "The server is genuine"),
		tr(lang,
			fmt.Sprintf("Защищённый чип %s внутри сервера подписал ответ на случайный вопрос, который ваш компьютер задал только что. Подделать такую подпись нельзя. Проверка сделана на вашем компьютере, а не на сервере.", chipMaker(s.provider)),
			fmt.Sprintf("The protected %s chip inside the server signed its answer to a random question your computer has just asked. That signature cannot be forged. The check ran on your computer, not on the server.", chipMaker(s.provider)))})
	o.Lines = append(o.Lines, bootLine(lang, s.provider))
	o.Lines = append(o.Lines, journalLine(lang, journalErr, len(events), st.Audit))

	restore := lastRestore(events)
	switch {
	case restore == nil:
		o.Lines = append(o.Lines, CheckLine{toneWarn, tr(lang, "Возврат модели ещё не проверялся", "Bringing the model back has not been checked"), tr(lang, "Нажмите «Проверить возврат модели».", "Press “Test bringing the model back”.")})
	case restore.OK:
		o.Lines = append(o.Lines, CheckLine{toneOK, tr(lang, "Модель возвращается точно такой же", "The model comes back exactly the same"),
			tr(lang,
				fmt.Sprintf("Последняя проверка %s: совпало %d из %d контрольных ответов, заняла %s с.", humanTime(restore.At), restore.Matched, restore.Matched, seconds(restore.Seconds)),
				fmt.Sprintf("Last check %s: %d of %d control answers matched, in %s s.", humanTime(restore.At), restore.Matched, restore.Matched, seconds(restore.Seconds)))})
	case st.Stop.StopAll:
		o.Lines = append(o.Lines, CheckLine{toneInfo, tr(lang, "Возврат модели сейчас запрещён", "Bringing the model back is forbidden now"), tr(lang, "Так и должно быть: включена аварийная остановка.", "As it should be: the emergency stop is on.")})
	case restore.Stopped:
		o.Lines = append(o.Lines, CheckLine{toneWarn, tr(lang, "Возврат модели давно не проверялся", "Bringing the model back has not been checked lately"), tr(lang, "Последнюю проверку запретила аварийная остановка. Теперь она снята: нажмите «Проверить возврат модели».", "The emergency stop forbade the last check. It is lifted now: press “Test bringing the model back”.")})
	default:
		o.Lines = append(o.Lines, CheckLine{toneBad, tr(lang, "Последняя проверка возврата не прошла", "The last check of bringing the model back failed"), tr(lang, "Модель не вернулась или не совпала с оригиналом. Подробности в журнале. Сообщите в ИТ-отдел.", "The model did not come back or did not match the original. See the journal for details and tell your IT department.")})
	}

	mine := a.publicKeyHex()
	holder := ""
	for _, p := range st.People {
		if p.PublicKeyHex == st.Stop.HolderPublicKeyHex {
			holder = p.Name
		}
		o.People = append(o.People, PersonLine{Name: p.Name, Role: roleText(lang, p.Role), PublicKeyHex: p.PublicKeyHex, HoldsStop: p.PublicKeyHex == st.Stop.HolderPublicKeyHex, You: p.PublicKeyHex == mine})
	}
	o.CanStop = st.Stop.HolderPublicKeyHex == mine && st.Stop.Serial > 0
	o.Stopped = st.Stop.StopAll
	o.StopReason = st.Stop.Reason
	switch {
	case st.Stop.Error != "":
		o.Lines = append(o.Lines, CheckLine{toneBad, tr(lang, "Аварийная остановка не читается", "The emergency stop cannot be read"), tr(lang, "Пока это так, сервер ничего не выдаёт. Сообщите в ИТ-отдел.", "While this lasts the server gives out nothing. Tell your IT department.")})
	case st.Stop.StopAll:
		o.Lines = append(o.Lines, CheckLine{toneBad, tr(lang, "Аварийная остановка включена", "The emergency stop is on"),
			tr(lang, "Сервер не выдаёт ключи от модели. Снять остановку может только "+holder+".", "The server gives out no keys to the model. Only "+holder+" can lift the stop.")})
	case st.Stop.HolderPublicKeyHex == "":
		o.Lines = append(o.Lines, CheckLine{toneWarn, tr(lang, "Аварийной остановки ни у кого нет", "Nobody holds the emergency stop"), tr(lang, "Её получает первый человек с полным доступом.", "The first person with full access receives it.")})
	default:
		o.Lines = append(o.Lines, CheckLine{toneOK, tr(lang, "Аварийная остановка готова", "The emergency stop is ready"),
			tr(lang, "Кнопка у: "+holder+". Ключ от неё есть только на компьютере этого человека, на сервере его нет.", "The button belongs to: "+holder+". Its key is only on that person's computer, not on the server.")})
	}
	others := a.otherServers(s)
	if len(others) == 0 {
		o.Lines = append(o.Lines, CheckLine{toneWarn, tr(lang, "Второго сервера нет", "There is no second server"),
			tr(lang, "Если этот сервер выйдет из строя, модель некуда перенести. Попросите ИТ-отдел развернуть второй и прислать вам на него пропуск.", "If this server fails, there is nowhere to move the model. Ask your IT department to deploy a second one and send you a pass for it.")})
	} else {
		names := make([]string, 0, len(others))
		for _, other := range others {
			names = append(names, other.pass.ServerLabel)
			o.Targets = append(o.Targets, TargetLine{ID: other.id, Label: other.pass.ServerLabel})
		}
		o.Lines = append(o.Lines, CheckLine{toneOK, tr(lang, "Есть куда перенести модель", "There is somewhere to move the model"),
			tr(lang, "Второй сервер: "+strings.Join(names, ", ")+". Перед переносом он снова докажет чипом, что настоящий.", "Second server: "+strings.Join(names, ", ")+". Before a move it proves again with its chip that it is genuine.")})
	}
	o.CanMove = o.CanStop && !st.Stop.StopAll

	warns := 0
	for _, l := range o.Lines {
		if l.Tone == toneWarn || l.Tone == toneBad {
			warns++
		}
	}
	switch {
	case o.Verdict == "offline":
	case st.Stop.StopAll:
		o.Verdict = "stopped"
		o.Headline = tr(lang, "Выдача остановлена", "Release is stopped")
		o.Subline = tr(lang, "Сервер не выдаёт ключи от модели. Рабочая модель банка при этом не выключается.", "The server gives out no keys to the model. The bank's running model is not switched off by this.")
	case warns > 0:
		o.Verdict = "attention"
		o.Headline = tr(lang, fmt.Sprintf("Работает. Замечаний: %d", warns), fmt.Sprintf("Working. Items to review: %d", warns))
		o.Subline = tr(lang, "Модель ИИ защищена, сервер подтвердил себя чипом. Ниже написано, что исправить.", "The AI model is protected and the server proved itself with its chip. See below what to fix.")
	default:
		o.Verdict = "ok"
		o.Headline = tr(lang, "Всё в порядке", "All is well")
		o.Subline = tr(lang, "Модель ИИ защищена, сервер подтвердил себя чипом.", "The AI model is protected and the server proved itself with its chip.")
	}
	return o
}

// bootLine says what the chip vouches for beyond the firmware.
func bootLine(lang string, p tee.Provider) CheckLine {
	if tee.QuotesTheBoot(p) {
		return CheckLine{toneOK, tr(lang, "Система сервера подтверждена", "The server's system is proved"),
			tr(lang, "Чип подтвердил и прошивку, и операционную систему. Они такие же, как в день установки.", "The chip proved both the firmware and the operating system. They are as they were on the day of installation.")}
	}
	return CheckLine{toneLimit, tr(lang, "Чип подтвердил прошивку, но не систему", "The chip proved the firmware, not the system"),
		tr(lang, "На этом типе сервера чип не проверяет операционную систему. Это ограничение типа сервера, а не поломка. Там, где это важно, выбирайте Google Cloud или Azure.", "On this type of server the chip does not check the operating system. That is a limit of the server type, not a fault. Where it matters, choose Google Cloud or Azure.")}
}

func journalLine(lang string, err error, checked int, audit console.AuditState) CheckLine {
	var broken *console.BrokenJournalError
	if errors.As(err, &broken) {
		return CheckLine{toneBad, tr(lang, "Журнал повреждён", "The journal is damaged"),
			tr(lang, fmt.Sprintf("Запись номер %d не прошла проверку подписи. Кто-то или что-то изменило журнал. Сообщите в ИТ-отдел.", broken.Index+1), fmt.Sprintf("Record number %d failed its signature check. Someone or something changed the journal. Tell your IT department.", broken.Index+1))}
	}
	if err != nil {
		return CheckLine{toneWarn, tr(lang, "Журнал сейчас не прочитан", "The journal could not be read just now"), plainError(lang, err)}
	}
	older := audit.Events - checked
	text := tr(lang,
		fmt.Sprintf("Проверено на вашем компьютере записей: %d. Каждая подписана и связана с предыдущей, поэтому незаметно изменить или удалить запись нельзя.", checked),
		fmt.Sprintf("Records checked on your computer: %d. Each is signed and linked to the one before, so a record cannot be changed or removed unnoticed.", checked))
	if older > 0 {
		text += tr(lang, fmt.Sprintf(" Ещё %d старых записей лежат в архиве сервера.", older), fmt.Sprintf(" Another %d older records are in the server's archive.", older))
	}
	return CheckLine{toneOK, tr(lang, "Журнал цел", "The journal is intact"), text}
}

func seconds(s float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.1f", s), "0"), ".")
}

func humanTime(t time.Time) string { return t.Local().Format("02.01.2006 15:04") }

// payloadOf reads an event's JSON body.
func payloadOf(e audit_event.AuditEvent) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(e.Payload, &m)
	return m
}

// evidenceStaleCode is the daemon's word for a worker told to attest again
// before it is handed a job: routine, and the job goes on.
const evidenceStaleCode = "evidence_stale"

// serverLabel is a name on a list as a person reads it: a server there goes by
// "<label> (server)", which says it twice in a sentence about a server.
func serverLabel(name string) string { return strings.TrimSuffix(name, " (server)") }

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// requester turns requester_identity into a name.
func requester(lang, id string) string {
	if name, ok := strings.CutPrefix(id, "person:"); ok {
		return name
	}
	return tr(lang, "Автоматическая система", "An automatic system")
}

// lastRestore finds the newest finished restore in the journal: from the
// request to the decision, or to the refusal.
func lastRestore(events []audit_event.AuditEvent) *RestoreLine {
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.Kind != audit_event.KindReleaseDecided && e.Kind != audit_event.KindIncidentTerminated && !isRefusal(e) {
			continue
		}
		line := &RestoreLine{At: e.OccurredAt}
		req := e.RequestID
		matched, level := 0, ""
		var start time.Time
		for j := i; j >= 0 && j > i-64; j-- {
			p := events[j]
			if p.Kind == audit_event.KindRequestReceived && p.RequestID == req {
				start = p.OccurredAt
				break
			}
			if isRefusal(p) && p.RequestID == req && str(payloadOf(p), "reason") == trust.ReasonOperatorStop {
				line.Stopped = true
			}
			if p.Kind == audit_event.KindValidationDimension {
				d, _ := payloadOf(p)["detail"].(map[string]any)
				if l, ok := d["level"].(string); ok {
					level = l
					if f, ok := d["fixtures"].(float64); ok {
						matched = int(f)
					}
				}
			}
		}
		if !start.IsZero() {
			line.Seconds = e.OccurredAt.Sub(start).Seconds()
		}
		line.Level, line.Matched = level, matched
		if e.Kind == audit_event.KindReleaseDecided {
			released, _ := payloadOf(e)["release"].(bool)
			line.OK = released && (level == "EXACT" || level == "EQUIVALENT")
		}
		return line
	}
	return nil
}

// isRefusal is a refusal of a job: one with a request behind it. A peer refused
// at its handshake is no restore that failed.
func isRefusal(e audit_event.AuditEvent) bool {
	return e.RequestID != "" && e.Kind == audit_event.KindTrustEvaluated && str(payloadOf(e), "outcome") == "deny"
}

// describe turns one record into a line a person reads. Minor lines are the
// steps inside a restore: shown only when a person asks for everything.
func describe(e audit_event.AuditEvent, idx int, lang string) (JournalLine, bool) {
	p := payloadOf(e)
	l := JournalLine{Index: idx, At: e.OccurredAt, Tone: toneInfo, Request: string(e.RequestID)}
	switch e.Kind {
	case audit_event.KindRequestReceived:
		who := requester(lang, str(p, "requester_identity"))
		l.Text = tr(lang, who+": запущена проверка возврата модели", who+": a check of bringing the model back was started")
	case audit_event.KindTrustEvaluated:
		if str(p, "outcome") == "allow" {
			l.Tone, l.Minor = toneOK, true
			l.Text = tr(lang, "Рабочий сервер доказал чипом, что он настоящий", "The worker server proved with its chip that it is genuine")
			break
		}
		if str(p, "code") == evidenceStaleCode {
			l.Tone, l.Minor = toneInfo, true
			l.Text = tr(lang, "Рабочий сервер подтверждает себя заново: прошлое подтверждение устарело", "The worker server is proving itself again: its last proof grew old")
			break
		}
		l.Tone = toneBad
		if strings.Contains(str(p, "reason"), "stop") {
			l.Text = tr(lang, "Отказано: включена аварийная остановка", "Refused: the emergency stop is on")
		} else {
			l.Text = tr(lang, "Рабочему серверу отказано: он не подтвердил себя", "The worker server was refused: it did not prove itself")
		}
	case audit_event.KindSessionIssued:
		l.Minor, l.Text = true, tr(lang, "Открыт защищённый сеанс с рабочим сервером", "A protected session with the worker server was opened")
	case audit_event.KindDisclosureAuthorized:
		l.Minor, l.Text = true, tr(lang, "Рабочему серверу передана часть модели", "A part of the model was passed to the worker server")
	case audit_event.KindManifestIssued:
		l.Minor, l.Text = true, tr(lang, "Рабочий сервер получил задание", "The worker server received its task")
	case audit_event.KindCandidateReceived:
		l.Minor, l.Text = true, tr(lang, "Рабочий сервер вернул результат на сравнение", "The worker server returned its result for comparison")
	case audit_event.KindValidationStarted:
		l.Minor, l.Text = true, tr(lang, "Началось сравнение с оригиналом", "Comparison with the original began")
	case audit_event.KindValidationDimension:
		d, _ := p["detail"].(map[string]any)
		level, _ := d["level"].(string)
		fixtures, _ := d["fixtures"].(float64)
		switch level {
		case "EXACT":
			l.Tone = toneOK
			l.Text = tr(lang, fmt.Sprintf("Модель вернулась точно такой же: %d контрольных ответов из %d совпали до последнего бита", int(fixtures), int(fixtures)), fmt.Sprintf("The model came back exactly the same: %d of %d control answers matched to the last bit", int(fixtures), int(fixtures)))
		case "EQUIVALENT":
			l.Tone = toneOK
			l.Text = tr(lang, fmt.Sprintf("Модель вернулась в пределах допуска: %d контрольных ответов", int(fixtures)), fmt.Sprintf("The model came back within tolerance: %d control answers", int(fixtures)))
		case "FAIL", "ERROR":
			l.Tone = toneBad
			l.Text = tr(lang, "Модель НЕ совпала с оригиналом", "The model did NOT match the original")
		default:
			l.Minor, l.Text = true, tr(lang, "Проверено ещё одно условие возврата", "One more condition of the return was checked")
		}
	case audit_event.KindValidationFinding:
		l.Tone, l.Text = toneWarn, tr(lang, "При сравнении найдено отличие", "The comparison found a difference")
	case audit_event.KindValidationCompleted:
		l.Minor, l.Text = true, tr(lang, "Сравнение завершено", "The comparison finished")
	case audit_event.KindReleaseDecided:
		if rel, _ := p["release"].(bool); rel {
			l.Tone, l.Text = toneOK, tr(lang, "Решение записано: модель принята", "Decision recorded: the model is accepted")
		} else {
			l.Tone, l.Text = toneBad, tr(lang, "Решение записано: модель не принята", "Decision recorded: the model is not accepted")
			// A refusal at the door has its own line already.
			l.Minor = strings.Contains(str(p, "reason"), "trust")
		}
	case audit_event.KindSessionInvalidated:
		l.Minor, l.Text = true, tr(lang, "Защищённый сеанс закрыт", "The protected session was closed")
	case audit_event.KindIncidentDetected:
		l.Tone, l.Text = toneBad, tr(lang, "Обнаружена опасность, сервер прервал работу", "A danger was detected and the server broke off the work")
	case audit_event.KindIncidentTerminated:
		l.Tone, l.Text = toneBad, tr(lang, "Работа прервана из-за опасности", "The work was ended because of a danger")
	case audit_event.KindKeyReleaseAuthorized:
		l.Tone, l.Text = toneOK, tr(lang, "Ключ от модели выдан другому подтверждённому серверу", "The key to the model was given to another proved server")
	case audit_event.KindKeyReleaseDenied:
		l.Tone, l.Text = toneBad, tr(lang, "В выдаче ключа от модели отказано", "Giving out the key to the model was refused")
	case audit_event.KindCrossCloudRestoreCompleted:
		l.Tone, l.Text = toneOK, tr(lang, "Модель восстановлена на другом сервере", "The model was restored on another server")
	case audit_event.KindFailoverDecided:
		l.Tone, l.Text = toneWarn, tr(lang, "Принято решение о переносе на резервный сервер", "A decision about moving to the backup server was taken")
	case audit_event.KindAuditSegmentClosed:
		l.Minor, l.Text = true, tr(lang, "Журнал: заполненный том ушёл в архив", "Journal: a full volume went to the archive")
	case audit_event.KindConsoleAction:
		who := serverLabel(str(p, "person"))
		// A server's place on a list for one move is a step of that move.
		l.Minor = console.Role(str(p, "role")) == console.RolePeer
		switch str(p, "action") {
		case console.ActionPersonJoined:
			l.Tone = toneOK
			l.Text = tr(lang, who+" получает доступ: "+roleText(lang, console.Role(str(p, "role"))), who+" gets access: "+roleText(lang, console.Role(str(p, "role"))))
		case console.ActionPersonRemoved:
			l.Tone = toneWarn
			l.Text = tr(lang, "Доступ закрыт: "+serverLabel(str(p, "subject"))+". Кто закрыл: "+who, "Access closed: "+serverLabel(str(p, "subject"))+". Closed by: "+who)
		case console.ActionInviteMade:
			l.Text = tr(lang, "Создан пропуск для: "+serverLabel(str(p, "subject"))+". Кто создал: "+who, "A pass was made for: "+serverLabel(str(p, "subject"))+". Made by: "+who)
		case console.ActionStopReady:
			l.Tone = toneOK
			l.Text = tr(lang, "Аварийная остановка готова. Кнопка у: "+who, "The emergency stop is ready. The button belongs to: "+who)
		case console.ActionStopSet:
			l.Tone = toneBad
			l.Text = tr(lang, "АВАРИЙНАЯ ОСТАНОВКА ВКЛЮЧЕНА. Кто: "+who, "THE EMERGENCY STOP WAS SWITCHED ON. By: "+who)
			if r := str(p, "reason"); r != "" {
				l.Text += tr(lang, ". Причина: "+r, ". Reason: "+r)
			}
		case console.ActionStopLifted:
			l.Tone = toneOK
			l.Text = tr(lang, "Аварийная остановка снята. Кто: "+who, "The emergency stop was lifted. By: "+who)
		case console.ActionMoveOrdered:
			l.Tone = toneWarn
			l.Text = tr(lang, "Приказ о переносе модели на сервер: "+str(p, "subject")+". Кто подписал: "+who, "An order to move the model to the server: "+str(p, "subject")+". Signed by: "+who)
		case console.ActionModelReleased:
			l.Tone = toneOK
			l.Text = tr(lang, "Новый сервер доказал чипом, что настоящий. Ключ от модели зашифрован так, что откроется только на нём: "+str(p, "subject"), "The new server proved with its chip that it is genuine. The model's key was locked so that it opens only there: "+str(p, "subject"))
		case console.ActionModelSent:
			l.Tone = toneOK
			l.Text = tr(lang, "Модель передана на сервер: "+str(p, "subject"), "The model was handed to the server: "+str(p, "subject"))
		case console.ActionModelReceived:
			l.Tone = toneOK
			l.Minor = strings.HasSuffix(str(p, "bundle"), ".escrow")
			l.Text = tr(lang, "Получена модель от сервера: "+who, "A model arrived from the server: "+who)
			if l.Minor {
				l.Text = tr(lang, "Получен ключ от модели, закрытый для этого сервера", "The model's key arrived, locked for this server")
			}
		default:
			return l, false
		}
	default:
		l.Minor, l.Text = true, tr(lang, "Служебная запись", "A service record")
	}
	return l, true
}

// stageText says what a restore check is doing now, and how far along it is.
func stageText(lang, state string) (string, int) {
	switch state {
	case "unstarted", "request", "trust":
		return tr(lang, "Рабочий сервер доказывает чипом, что он настоящий", "The worker server is proving with its chip that it is genuine"), 1
	case "session", "disclosure":
		return tr(lang, "Модель передаётся рабочему серверу частями", "The model is being passed to the worker server in parts"), 2
	case "external_compute", "return":
		return tr(lang, "Модель восстанавливается на рабочем сервере", "The model is being restored on the worker server"), 3
	case "validation":
		return tr(lang, "Ответы модели сравниваются с оригиналом", "The model's answers are being compared with the original"), 4
	default:
		return tr(lang, "Решение записывается в журнал", "The decision is being written to the journal"), 5
	}
}

// plainError says what went wrong in words a person can act on.
func plainError(lang string, err error) string {
	var api *apiError
	if errors.As(err, &api) {
		switch api.Code {
		case "not_listed":
			return tr(lang, "У вас больше нет доступа к этому серверу. Обратитесь к владельцу.", "You no longer have access to this server. Ask its owner.")
		case "role_refused":
			return tr(lang, "Ваш доступ этого не позволяет.", "Your access does not allow this.")
		case "invite_unknown":
			return tr(lang, "Этот пропуск уже использован или не существует. Попросите новый.", "This pass was already used or does not exist. Ask for a new one.")
		case "invite_expired":
			return tr(lang, "Срок этого пропуска истёк. Попросите новый.", "This pass has expired. Ask for a new one.")
		case "no_genome":
			return tr(lang, "На сервере ещё нет запечатанной модели.", "There is no sealed model on the server yet.")
		case "order_refused":
			return tr(lang, "Сервер не принял приказ: он подписан не тем, кто держит кнопку, или устарел.", "The server did not accept the order: it is not signed by the holder of the button, or it is out of date.")
		case "order_used":
			return tr(lang, "Этот приказ уже выполнен.", "This order was already carried out.")
		case "stopped":
			return tr(lang, "На этом сервере включена аварийная остановка, поэтому он ничего не передаёт.", "The emergency stop is on at this server, so it hands nothing over.")
		case "target_stopped":
			return tr(lang, "На новом сервере включена аварийная остановка. Сначала снимите её там.", "The emergency stop is on at the new server. Lift it there first.")
		case "target_unproven":
			return tr(lang, "Новый сервер не доказал, что он настоящий. Ничего не передано.", "The new server did not prove it is genuine. Nothing was handed over.")
		case "target_refused":
			return tr(lang, "Новый сервер не впустил этот сервер. Ничего не передано. Проверьте, что они видят друг друга по сети.", "The new server did not let this one in. Nothing was handed over. Check that they can reach each other over the network.")
		case "target_no_key":
			return tr(lang, "Новый сервер не готов принимать модели. Сообщите в ИТ-отдел.", "The new server is not ready to receive models. Tell your IT department.")
		case "already_here":
			return tr(lang, "Такая модель уже есть на новом сервере.", "This model is already on the new server.")
		case "target_is_source":
			return tr(lang, "Это тот же самый сервер.", "This is the same server.")
		case "move_failed":
			return tr(lang, "Перенос не закончился. Старый сервер продолжает работать как прежде.", "The move did not finish. The old server keeps working as before.")
		case "list_old":
			return tr(lang, "На сервере уже действует более новое решение. Обновите страницу.", "A newer decision is already in force on the server. Refresh the page.")
		case "list_refused":
			return tr(lang, "Сервер не принял подпись: кнопка остановки не у вас.", "The server did not accept the signature: the stop button is not yours.")
		case "chip_unavailable":
			return tr(lang, "Чип сервера не ответил. Сообщите в ИТ-отдел.", "The server's chip did not answer. Tell your IT department.")
		case "audit_unavailable":
			return tr(lang, "Сервер не смог сделать запись в журнал, поэтому ничего не изменил.", "The server could not write to the journal, so it changed nothing.")
		}
		return api.Message
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate"):
		return tr(lang, "Адрес отвечает, но это не тот сервер, что в вашем пропуске.", "The address answers, but it is not the server in your pass.")
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"), strings.Contains(msg, "refused"), strings.Contains(msg, "no route"):
		return tr(lang, "Сервер не отвечает. Проверьте интернет или сообщите в ИТ-отдел.", "The server does not answer. Check your internet connection or tell your IT department.")
	}
	var broken *console.BrokenJournalError
	if errors.As(err, &broken) {
		return tr(lang, fmt.Sprintf("Запись номер %d не прошла проверку.", broken.Index+1), fmt.Sprintf("Record number %d failed its check.", broken.Index+1))
	}
	return tr(lang, "Ответ сервера не прошёл проверку на вашем компьютере.", "The server's answer failed the check on your computer.")
}

func containsStop(s string) bool {
	return strings.Contains(strings.ToLower(s), "stop")
}
