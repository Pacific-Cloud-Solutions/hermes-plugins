// AI Chipmunk — connect this machine's Hermes bots to the AI Chipmunk app.
//
// Renders the pairing code inside Hermes Desktop, so pairing no longer needs a
// terminal: open this page, pick a bot, scan the code with the phone.
//
// Imports are limited to the plugin SDK and React (the file loads uncompiled, so
// it uses jsx() calls rather than JSX syntax and references only what it imports).

import {
  host,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  PALETTE_AREA,
  Button
} from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'
import { useCallback, useEffect, useState } from 'react'

const PATH = '/aichipmunk'
const POLL_MS = 20000
const LAST_PROFILE_KEY = 'lastProfile'

// The app's own logo, inlined. A plugin is a single uncompiled ESM file, so
// an asset path would not resolve — and an <img> cannot send the session
// token the plugin backend requires, so a served URL is not an option.
// 128px source, drawn at 56pt.
const LOGO_DATA_URI =
  'data:image/png;base64,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'

const APP_STORE_URL = 'https://apps.apple.com/us/app/ai-chipmunk/id6751478863'
const GOOGLE_PLAY_URL =
  'https://play.google.com/store/apps/details?id=pacificcloudsolutions.aichipmunk'

// The backend namespace (/api/plugins/aichipmunk) is reachable only through the
// context handed to register(); components read it from here.
let api = null

// Opening a store page is the OS's job; a refusal is reported, never swallowed.
async function openStore(url) {
  try {
    const opened = await api.os.openExternal(url)
    if (!opened) {
      host.notify({ kind: 'error', message: 'Could not open the store page.' })
    }
  } catch {
    host.notify({ kind: 'error', message: 'Could not open the store page.' })
  }
}

function Line({ label, value, mono = false }) {
  if (!value) return null
  return jsxs('div', {
    className: 'flex items-baseline justify-between gap-3 py-0.5 text-sm',
    children: [
      jsx('span', { className: 'text-(--ui-text-secondary) shrink-0', children: label }),
      jsx('span', {
        className: mono
          ? 'font-mono text-(--ui-text-primary) truncate'
          : 'text-(--ui-text-primary) truncate',
        children: value
      })
    ]
  })
}

function Dot({ state }) {
  const color =
    state === 'ok'
      ? 'var(--ui-accent)'
      : state === 'bad'
        ? 'var(--ui-warning, currentColor)'
        : 'var(--ui-stroke-secondary)'
  return jsx('span', {
    'aria-hidden': 'true',
    style: {
      display: 'inline-block',
      width: '6px',
      height: '6px',
      borderRadius: '9999px',
      backgroundColor: color,
      marginRight: '6px'
    }
  })
}

function BotRow({ bot, selected, onSelect, anywhereUrl, wifiUrl }) {
  // Selection is per (profile, ADDRESS): the two buttons are two separate
  // gateways in the app's registry, so pairing one must leave the other usable.
  // Scoping to the row's own profile prevents one bot's selection from lighting
  // every row that shares the same machine-level address.
  const wifiSelected = Boolean(
    selected && selected.profile === bot.profile && wifiUrl && selected.host === wifiUrl
  )
  const anywhereSelected = Boolean(
    selected && selected.profile === bot.profile && anywhereUrl && selected.host === anywhereUrl
  )
  return jsxs('div', {
    className:
      'flex items-center justify-between gap-3 rounded-md border border-(--ui-stroke-secondary) px-3 py-2',
    children: [
      jsxs('div', {
        className: 'min-w-0',
        children: [
          jsx('div', { className: 'text-sm font-medium truncate', children: bot.label }),
          jsx('div', {
            className: 'text-xs text-(--ui-text-tertiary) truncate',
            children: bot.pairable
              ? `${bot.profile} · key ${bot.key_hint}`
              : `${bot.profile} · no API key configured`
          })
        ]
      }),
      jsxs('div', {
        className: 'flex shrink-0 items-center gap-2',
        children: [
          // The SAME bot under each network it can be reached on. Two entries
          // beat one: Wi-Fi needs no Tailscale at home, the tailnet name works
          // anywhere, and neither address covers both cases.
          wifiUrl
            ? jsx(Button, {
                disabled: !bot.pairable || wifiSelected,
                onClick: () => onSelect(bot.profile, wifiUrl),
                children: wifiSelected ? 'Selected' : 'Wifi'
              })
            : null,
          anywhereUrl
            ? jsx(Button, {
                disabled: !bot.pairable || anywhereSelected,
                onClick: () => onSelect(bot.profile, anywhereUrl),
                children: anywhereSelected ? 'Selected' : 'Tailscale'
              })
            : null
        ]
      })
    ]
  })
}

function PairingCard({ result }) {
  const [copied, setCopied] = useState(false)

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(result.link)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      host.notify({ kind: 'error', message: 'Could not copy the link.' })
    }
  }, [result.link])

  return jsxs('div', {
    className: 'flex flex-col gap-3 rounded-md border border-(--ui-stroke-secondary) p-4',
    children: [
      jsx('div', {
        className: 'text-sm font-medium',
        children: `Scan this with AI Chipmunk — ${result.label}`
      }),
      jsxs('div', {
        className: 'flex items-start gap-4',
        children: [
          jsx('img', {
            src: result.qr,
            alt: `Pairing code for ${result.label}`,
            style: { width: '180px', height: '180px' }
          }),
          jsxs('div', {
            className: 'min-w-0 flex-1',
            children: [
              jsx(Line, { label: 'Host', value: result.host, mono: true }),
              jsx(Line, { label: 'Bot', value: result.profile }),
              jsx(Line, { label: 'Key', value: result.key_hint, mono: true }),
              jsxs('div', {
                className: 'flex items-center py-0.5 text-sm',
                children: [
                  jsx(Dot, { state: result.reachable ? 'ok' : 'bad' }),
                  jsx('span', {
                    className: 'text-(--ui-text-secondary)',
                    children: result.reachable
                      ? 'Reachable from this machine'
                      : 'Did not answer yet — the phone must be on the same network'
                  })
                ]
              }),
              jsx('div', {
                className: 'pt-2',
                children: jsx(Button, {
                  onClick: copy,
                  children: copied ? 'Copied' : 'Copy link'
                })
              })
            ]
          })
        ]
      }),
      jsx('div', {
        className: 'text-xs text-(--ui-text-tertiary)',
        children:
          'This code is a credential while it is on screen. The phone must be able to reach that host.'
      })
    ]
  })
}

function headlessMount(message) {
  const text = String(message || '')
  return /web UI disabled|Headless backend/i.test(text) || /\b404\b/.test(text)
}

function explain(message) {
  return headlessMount(message)
    ? 'This plugin is enabled, but its backend is not running in this window yet.'
    : String(message || 'Something went wrong.')
}

function AiChipmunkPage() {
  const [state, setState] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [tailnetConfirm, setTailnetConfirm] = useState(false)
  const [tailnetResult, setTailnetResult] = useState(null)

  const load = useCallback(async () => {
    try {
      setState(await api.rest('/state'))
    } catch (e) {
      setError(e && e.message ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const pair = useCallback(async (profile, host) => {
    setBusy(true)
    setError('')
    try {
      // `host` is the anywhere address when pairing for off-network use; omitting
      // it lets the server pick the bind that answers.
      const body = host ? { profile, host } : { profile }
      const data = await api.rest('/pair', { method: 'POST', body })
      setResult(data)
      try {
        await api.storage.set(LAST_PROFILE_KEY, profile)
      } catch {
        // remembering the choice is a convenience, never a requirement
      }
    } catch (e) {
      setResult(null)
      setError(e && e.message ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  // "Reach these bots from anywhere": ask first, because the action restarts
  // the gateway that owns the listening socket and drains in-flight runs.
  const useTailscale = useCallback(async () => {
    setBusy(true)
    setError('')
    try {
      const data = await api.rest('/use-tailscale', {
        method: 'POST',
        body: { confirm: true }
      })
      setTailnetResult(data)
      setTailnetConfirm(false)
      await load()
      host.notify({
        kind: data.reachable ? 'success' : 'error',
        message: data.detail || 'Bind updated.'
      })
    } catch (e) {
      setError(e && e.message ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }, [load])

  const bots = (state && state.bots) || []
  // A bot with no key is still a bot. Filtering it out made this page disagree
  // with the mobile app, whose roster lists EVERY profile on the machine — so a
  // bot the user could see on the phone simply vanished here, with nothing
  // saying why. List them all; the row itself explains the missing key.
  const unpairable = bots.filter((b) => !b.pairable)

  return jsxs('div', {
    className: 'flex h-full flex-col gap-4 overflow-y-auto p-5 text-sm',
    children: [
      jsxs('div', {
        className: 'flex items-start gap-4',
        children: [
          // Decorative: the wordmark right beside it already names the product.
          jsx('img', {
            src: LOGO_DATA_URI,
            alt: '',
            width: 56,
            height: 64,
            className: 'shrink-0'
          }),
          jsxs('div', {
            className: 'flex flex-col gap-1',
            children: [
              jsx('div', {
                className: 'text-base font-medium',
                children: 'AI Chipmunk'
              }),
              jsx('div', {
                className: 'text-(--ui-text-secondary)',
                children:
                  "Chat with this machine's Hermes agents from your phone. Every " +
                  'Hermes profile is a bot — pick one below and Hermes shows a ' +
                  'pairing code; scan it with the AI Chipmunk app to connect. ' +
                  'Nothing is exposed to the internet: the code carries this ' +
                  "machine's address and that bot's own key."
              })
            ]
          })
        ]
      }),
      // The app is the other half of this page, so say where to get it.
      jsxs('div', {
        className: 'flex flex-wrap items-center gap-2',
        children: [
          jsx('span', {
            className: 'text-(--ui-text-secondary)',
            children: 'Need the app? Get AI Chipmunk from'
          }),
          jsx(Button, {
            onClick: () => void openStore(APP_STORE_URL),
            children: 'App Store'
          }),
          jsx(Button, {
            onClick: () => void openStore(GOOGLE_PLAY_URL),
            children: 'Google Play'
          })
        ]
      }),
      // The BIND decides who can reach the server, so report the verdict rather
      // than implying an address works. One tap changes it, once Tailscale is up.
      state && state.bind_verdict
        ? jsxs('div', {
            className:
              'flex flex-col gap-2 rounded-md border p-3 text-(--ui-text-secondary)',
            style: { borderColor: 'var(--ui-stroke-secondary)' },
            children: [
              jsx('span', { children: state.guidance || '' }),
              !state.tailnet && state.bind_verdict === 'home_only'
                ? jsx(Button, {
                    onClick: () => void api.os.openExternal('https://tailscale.com/download'),
                    children: 'Get Tailscale for this machine'
                  })
                : null,
              state.can_reach_anywhere && !state.dashboard_ready
                ? jsxs('div', {
                    className: 'flex flex-col gap-2 text-xs text-(--ui-text-tertiary)',
                    children: [
                      state.dashboard_approval_url
                        ? jsxs('div', {
                            className: 'flex flex-col gap-2',
                            children: [
                              'Tailscale must allow HTTPS on this tailnet before the app can list all your bots.',
                              jsxs('div', {
                                className: 'flex flex-wrap items-center gap-2',
                                children: [
                                  jsx(Button, {
                                    onClick: () =>
                                      void api.os.openExternal(state.dashboard_approval_url),
                                    children: 'Open approval page'
                                  }),
                                  jsx(Button, {
                                    onClick: async () => {
                                      try {
                                        await navigator.clipboard.writeText(
                                          state.dashboard_approval_url
                                        )
                                        host.notify({
                                          kind: 'success',
                                          message: 'Link copied to clipboard.'
                                        })
                                      } catch {
                                        host.notify({
                                          kind: 'error',
                                          message: 'Could not copy the link.'
                                        })
                                      }
                                    },
                                    children: 'Copy link'
                                  })
                                ]
                              })
                            ]
                          })
                        : jsxs('div', {
                            children: [
                              'This machine can reach the internet via Tailscale, but the dashboard is not published. Run ',
                              jsx('code', { children: 'hermes dashboard register' }),
                              ' in Terminal.'
                            ]
                          })
                    ]
                  })
                : null,
              state.needs_bind_change && !tailnetResult
                ? tailnetConfirm
                  ? jsxs('div', {
                      className: 'flex flex-row flex-wrap items-center gap-2',
                      children: [
                        jsx('span', {
                          className: 'text-(--ui-text-tertiary)',
                          children:
                            `Binds the API server to ${state.tailnet} and restarts ` +
                            `the '${state.owner}' gateway. Runs in progress drain.`
                        }),
                        jsx(Button, {
                          onClick: () => void useTailscale(),
                          disabled: busy,
                          children: busy ? 'Switching...' : 'Switch to Tailscale'
                        }),
                        jsx(Button, {
                          onClick: () => setTailnetConfirm(false),
                          disabled: busy,
                          children: 'Cancel'
                        })
                      ]
                    })
                  : jsx(Button, {
                      onClick: () => setTailnetConfirm(true),
                      disabled: busy,
                      children: 'Reach these bots from anywhere'
                    })
                : null,
              tailnetResult
                ? jsx('span', {
                    children: tailnetResult.reachable
                      ? `Now listening on ${tailnetResult.address}. Re-pair from the ` +
                        'app to pick up the new address.'
                      : String(tailnetResult.detail || '')
                  })
                : null
            ]
          })
        : null,
      error
        ? jsxs('div', {
            className: 'flex flex-col gap-2 text-(--ui-text-secondary)',
            children: [
              jsx('div', { children: explain(error) }),
              headlessMount(error)
                ? jsx('div', {
                    className: 'text-xs text-(--ui-text-tertiary)',
                    children:
                      'Enabling a plugin loads its page right away, but its backend mounts when Hermes starts. Quit and reopen Hermes, then try again.'
                  })
                : null
            ]
          })
        : null,
      !state && !error
        ? jsx('div', { className: 'text-(--ui-text-tertiary)', children: 'Loading bots…' })
        : null,
      !state && error
        ? jsx(Button, { onClick: () => void load(), children: 'Try again' })
        : null,
      state && !bots.length
        ? jsxs('div', {
            className: 'text-(--ui-text-secondary)',
            children: [
              jsx('div', { children: 'No Hermes profile found on this machine.' }),
              jsx('div', {
                className: 'text-xs text-(--ui-text-tertiary)',
                children: 'A bot is a Hermes profile. Create one, then reopen this page.'
              })
            ]
          })
        : null,
      bots.length
        ? jsxs('div', {
            className: 'flex flex-col gap-2',
            children: [
              jsx('div', {
                className: 'text-xs uppercase tracking-wide text-(--ui-text-tertiary)',
                children: 'Bots on this machine'
              }),
              ...bots.map((bot) =>
                jsx(
                  BotRow,
                  {
                    bot,
                    selected: result
                      ? { profile: result.profile, host: result.host }
                      : null,
                    wifiUrl: bot.wifi_url || '',
                    anywhereUrl: bot.anywhere_url || state.tailnet_url || '',
                    onSelect: (p, h) => void pair(p, h)
                  },
                  bot.profile
                )
              ),
              // Name the fix rather than leaving a disabled row unexplained.
              unpairable.length
                ? jsx('div', {
                    className: 'text-xs text-(--ui-text-tertiary)',
                    children:
                      `No API key yet: ${unpairable.map((b) => b.profile).join(', ')}. ` +
                      "Add API_SERVER_KEY to that profile's .env, then reopen this page."
                  })
                : null
            ]
          })
        : null,
      busy
        ? jsx('div', { className: 'text-(--ui-text-tertiary)', children: 'Building a code…' })
        : null,
      result ? jsx(PairingCard, { result }) : null
    ]
  })
}

function StatusChip() {
  const [status, setStatus] = useState('unknown')

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const data = await api.rest('/state')
        if (!alive) return
        const anyPairable = (data.bots || []).some((b) => b.pairable)
        setStatus(anyPairable ? 'unknown' : 'bad')
      } catch {
        if (alive) setStatus('bad')
      }
    }
    void tick()
    const timer = setInterval(() => void tick(), POLL_MS)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [])

  return jsx('button', {
    type: 'button',
    onClick: () => host.navigate(PATH),
    className: 'flex items-center px-2 text-xs text-(--ui-text-secondary) hover:text-(--ui-text-primary)',
    children: jsxs('span', {
      className: 'flex items-center',
      children: [jsx(Dot, { state: status }), 'AI Chipmunk']
    })
  })
}

export default {
  id: 'aichipmunk',
  name: 'AI Chipmunk',
  register(ctx) {
    api = ctx

    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: PATH },
        render: () => jsx(AiChipmunkPage, {})
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        data: { path: PATH, label: 'AI Chipmunk', codicon: 'plug' }
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'aichipmunk.open',
          label: 'Connect AI Chipmunk',
          keywords: ['aichipmunk', 'pair', 'bot', 'phone', 'mobile'],
          run: () => host.navigate(PATH)
        }
      },
      {
        id: 'chip',
        area: STATUSBAR_AREAS.right,
        order: 90,
        render: () => jsx(StatusChip, {})
      }
    ])
  }
}