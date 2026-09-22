# PII Guard

[![selftest](https://github.com/milkywebboy/claude-pii-guard/actions/workflows/test.yml/badge.svg)](https://github.com/milkywebboy/claude-pii-guard/actions/workflows/test.yml)

**Claude Code に送る前に、個人情報と認証情報をローカルで止めるプラグイン。**

コーディングエージェントに打つプロンプトは、そのままリモートのモデルに送られます。
顧客のメールアドレス、スタックトレースに混ざった本番トークン、貼り付けたログの中の電話番号。
一度 Enter を押したら取り消せません。

PII Guard は `UserPromptSubmit` フックとして動き、**送信前に**プロンプトを検査して止めます。
ネットワーク通信なし、外部依存なし、テレメトリなし。Python 標準ライブラリだけの 1 ファイルです。

```
🛑 個人情報の可能性があるため、Claude への送信を止めました（PII Guard）

  ・メールアドレス: 1件  例: yut********com
  ・電話番号: 1件  例: 090*******678

マスク済みの本文をクリップボードにコピーしました（貼り直せます）
元の本文の退避先: ~/.claude/pii-guard/blocked/20260922-200812.txt
意図的に送る場合は、本文のどこかに #pii-ok を書いて再送してください
```

## インストール

```bash
claude plugin marketplace add milkywebboy/claude-pii-guard
claude plugin install pii-guard@claude-pii-guard
```

対話セッション内からは `/plugin marketplace add milkywebboy/claude-pii-guard` でも同じです。
**インストール後、Claude Code の再起動が必要です。**

効いているかの確認:

```bash
claude -p "連絡先は 090-1234-5678 です"
```

`🛑 個人情報の可能性があるため、Claude への送信を止めました` と出れば成功です。

### 動作環境

- **Claude Code v2.1.30 以降**（`UserPromptSubmit` フック対応版）
- **Python 3.8 以降**（macOS と多くの Linux には標準で入っています）
- macOS / Linux で検証済み。Windows は未検証です（`python3` の解決とクリップボード連携が未確認）

### インストールする前に

これは**あなたが打つ全てのプロンプトを読むフック**です。他人の作ったそういうものを、中身を見ずに入れるべきではありません。

[`scripts/pii_guard.py`](scripts/pii_guard.py) がその全てです。依存ゼロの 1 ファイル、498 行。
ネットワーク通信は一切ありません（`import` に `urllib` も `requests` もないことを確認できます）。

## 検出するもの

| 種別 | 判定方法 |
|---|---|
| 秘密鍵 | `-----BEGIN ... PRIVATE KEY-----` |
| APIキー / トークン | AWS・GitHub・Anthropic・OpenAI・Slack・GCP・GitLab・Stripe 等の形式 |
| JWT | 3 セグメント構造 |
| パスワード / 認証情報 | `PASSWORD=`, `secret:`, `パスワードは` 等（プレースホルダは除外） |
| クレジットカード番号 | **Luhn チェック** + ブランド接頭辞。決済事業者が公開するテスト番号（`4242...` 等 18 種）は除外 |
| マイナンバー | **チェックデジット検証**、またはキーワード + 12桁。同一数字の繰り返しは除外 |
| 口座番号 / パスポート番号 | キーワード同伴時のみ |
| メールアドレス | 除外ドメイン以外 |
| 電話番号 | 日本の固定・携帯・`+81`（桁数検証あり）。`0120`/`0800`/`0570` は除外 |
| 郵便番号 | `〒` + 7桁 |
| **住所** | 都道府県あり・なしの両形式、郡部、`1-2-3` と `1丁目2番3号` の両表記 |

単なる正規表現の羅列ではなく、**チェックサム検証・キーワード同伴条件・除外リスト**で誤検知を抑えています。
とくに住所は、同種のツールがどれも実装していない領域です。

## 誤検知しないもの

セマンティックバージョン、ISO 日付、コミット SHA、UUID、`localhost:3000`、
`os.getenv("API_KEY")`、`your_password_here`、ポート範囲、金額、16進カラーコード、
**決済のテストカード番号**、**フリーダイヤル**、`地区1-2`、`横浜市西区の店舗1-2` など。

開発者がテストカード番号やフリーダイヤルを貼るのは正当な作業です。それを止めるツールは現場で使われません。

```bash
python3 scripts/pii_guard.py --selftest   # 56 ケース（検出 26 / 誤検知 21 / 独自ルール 9）
```

## 設定

以下の順に読み込まれ、後のものが優先されます。

1. `config.default.json`（プラグイン同梱）
2. `~/.claude/pii-guard.config.json`（個人設定）
3. `$CLAUDE_PROJECT_DIR/.claude/pii-guard.json`（リポジトリ設定・コミット可）

```json
{
  "rules": {
    "address": "warn",    // block: 送信を止める / warn: Claude に注意喚起 / off: 無効
    "email": "off"
  },
  "allow_patterns": ["@mycompany\\.example$"],
  "bypass_marker": "#pii-ok",
  "copy_masked_to_clipboard": true,
  "retention_days": 7
}
```

チームで配る場合は 3 のリポジトリ設定に置くと、クローンした全員に同じポリシーが効きます。

## 独自ルールを追加する

社員番号、顧客ID、社内システムの識別子 — 守りたいものは組織ごとに違います。
設定に `custom_rules` を足すだけで検出器を増やせます。**コード変更もビルドも不要です。**

```json
{
  "custom_rules": [
    {
      "id": "employee_id",
      "label": "社員番号",
      "pattern": "EMP-[0-9]{6}",
      "severity": "block"
    }
  ]
}
```

| フィールド | 必須 | 説明 |
|---|---|---|
| `id` | ✓ | ルールの識別子。`rules` で severity を上書きするときにも使う |
| `pattern` | ✓ | Python の正規表現 |
| `label` | | 表示名。既定は `id` |
| `severity` | | `block`（既定）/ `warn` / `off` |
| `flags` | | `i` 大文字小文字無視、`m`、`s`、`x` |
| `requires` | | この正規表現が本文のどこかに無ければ発火しない |
| `validate` | | `luhn` または `mynumber`。一致部分の数字でチェックサムを検証 |

### 書いて、試す

設定に入れる前に、その場で試せます。

```bash
python3 scripts/pii_guard.py --test-rule 'EMP-[0-9]{6}' '担当は EMP-104829 です'
```

一致箇所と、そのまま貼り付けられる設定 JSON が出力されます。

```bash
python3 scripts/pii_guard.py --rules
```

今どのルールが、どの設定ファイルから効いているかを一覧できます。

### 誤検知を減らす2つの道具

**`requires`** — `A-9931` のような短い ID は、そのままでは型番と区別できません。

```json
{"id": "case_id", "label": "案件番号", "pattern": "A-[0-9]{4}", "requires": "案件|チケット"}
```

本文に「案件」または「チケット」がある時だけ発火します。

**`validate`** — 桁数だけ合う数字を落とせます。

```json
{"id": "member_no", "label": "会員番号", "pattern": "MB[0-9]{10}", "validate": "luhn"}
```

### チームのルールと個人のルールは共存する

`custom_rules` は**層をまたいで足し算**されます。上書きではありません。

- 組織の必須ルール → リポジトリの `.claude/pii-guard.json`（コミットする）
- 自分だけのルール → `~/.claude/pii-guard.config.json`

同じ `id` があれば上の層（プロジェクト）が勝ちます。

壊れたルールは **警告を出してスキップ** されます。誰か1人の正規表現の打ち間違いで、
全員のプロンプトが止まることはありません。

## 仕組み

```
プロンプト入力 → UserPromptSubmit フック → pii_guard.py（ローカル）
                                              ├─ 検出なし → exit 0 → Claude へ送信
                                              ├─ warn    → exit 0 + Claude に注意喚起
                                              └─ block   → exit 2 → 送信されない
                                                            ├ 元の本文を 0600 で退避
                                                            └ マスク済み本文をクリップボードへ
```

Claude Code の `UserPromptSubmit` はプロンプト本文の書き換え（`updatedInput`）に対応していないため、
**ブロック + マスク済み本文をクリップボードに置く**という形で「書き換えて送り直す」を実現しています。

## 限界（正直に）

- 対象は**入力したプロンプトのみ**です。Claude が読むファイルの中身、貼り付けた画像、
  Web 版 claude.ai は対象外です。
- 正規表現ベースなので万能ではありません。氏名、番地のない住所、自由記述の機微情報は検出できません。
- スクリプト自体がエラーになった場合は作業を止めないよう **fail-open**（警告を出して通過）です。
  厳格にしたい場合は `main()` の例外処理を `sys.exit(2)` に変えてください。

**最後の砦ではなく、うっかり防止です。**

## ロードマップ

- `PreToolUse` フックで、Claude が読み込むファイルの中身も検査する
- 英語圏の PII（SSN、UK NIN、IBAN）対応

## License

MIT
