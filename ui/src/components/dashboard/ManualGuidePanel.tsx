import ReactMarkdown from 'react-markdown'
import { useState } from 'react'
import { BookOpen, Loader2, Copy, Check, ExternalLink } from 'lucide-react'

interface ManualGuidePanelProps {
  guide: string | null
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center space-x-1 px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition text-[9px] font-mono ml-2"
    >
      {copied ? (
        <>
          <Check className="w-2.5 h-2.5 text-emerald-400" />
          <span className="text-emerald-400">Copied!</span>
        </>
      ) : (
        <>
          <Copy className="w-2.5 h-2.5" />
          <span>Copy</span>
        </>
      )}
    </button>
  )
}

function CodeBlock({ children, className }: { children: React.ReactNode; className?: string }) {
  const text = typeof children === 'string' ? children : String(children)
  const isCommand = text.startsWith('curl ') || text.startsWith('nuclei ') || text.startsWith('http ') || text.startsWith('$')
  
  return (
    <div className="relative group">
      <pre className={`${className || ''} bg-zinc-900/80 border border-zinc-800 rounded p-3 pr-16 overflow-x-auto text-[11px] font-mono text-amber-400`}>
        <code>{children}</code>
      </pre>
      <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition">
        <CopyButton text={text} />
      </div>
      {isCommand && (
        <div className="absolute top-2 right-20 opacity-0 group-hover:opacity-100 transition">
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault()
              navigator.clipboard.writeText(text)
            }}
            className="text-[9px] font-mono text-zinc-500 hover:text-amber-400 flex items-center space-x-1"
          >
            <ExternalLink className="w-2.5 h-2.5" />
            <span>Run</span>
          </a>
        </div>
      )}
    </div>
  )
}

export default function ManualGuidePanel({ guide }: ManualGuidePanelProps) {
  if (!guide) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center text-zinc-600 space-y-4 p-8 text-center">
        <Loader2 className="w-8 h-8 animate-spin opacity-20" />
        <div className="space-y-1">
          <p className="text-xs font-mono uppercase tracking-widest">Generating Guide...</p>
          <p className="text-[10px] font-mono opacity-50">Running security tools and mapping vulnerabilities. Your step-by-step manual hacking guide will appear here once ready.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto p-2 space-y-6 custom-scrollbar">
      <div className="flex items-center space-x-2 text-amber-500 mb-4 px-2">
        <BookOpen className="w-4 h-4" />
        <span className="text-[10px] font-mono uppercase tracking-widest font-bold">Step-by-Step Manual Exploitation Guide</span>
      </div>
      
      <div className="prose prose-invert prose-zinc max-w-none px-2 
        prose-headings:font-mono prose-headings:uppercase prose-headings:tracking-tighter
        prose-h1:text-xl prose-h2:text-lg prose-h3:text-md
        prose-p:text-xs prose-p:leading-relaxed prose-p:text-zinc-400
        prose-li:text-xs prose-li:text-zinc-400
        prose-code:text-amber-400 prose-code:bg-amber-500/10 prose-code:px-1 prose-code:rounded prose-code:before:content-none prose-code:after:content-none
        prose-strong:text-zinc-100 prose-strong:font-bold
        prose-a:text-amber-400 prose-a:no-underline hover:prose-a:underline
        border-t border-zinc-900 pt-6">
        <ReactMarkdown
          components={{
            code({ node, className, children, ...props }) {
              const match = /language-(\w+)/.exec(className || '')
              const isInline = !match && !className
              if (isInline) {
                return (
                  <code className="bg-amber-500/10 text-amber-400 px-1 py-0.5 rounded text-[11px]" {...props}>
                    {children}
                  </code>
                )
              }
              return (
                <CodeBlock className={className}>{children}</CodeBlock>
              )
            },
            table({ children }) {
              return (
                <div className="overflow-x-auto my-4">
                  <table className="min-w-full border border-zinc-800 rounded">{children}</table>
                </div>
              )
            },
            th({ children }) {
              return (
                <th className="px-3 py-2 text-left text-[10px] font-mono uppercase tracking-wider text-zinc-400 bg-zinc-900/50 border-b border-zinc-800">
                  {children}
                </th>
              )
            },
            td({ children }) {
              return (
                <td className="px-3 py-2 text-[11px] font-mono text-zinc-300 border-b border-zinc-900/50">
                  {children}
                </td>
              )
            },
            a({ href, children }) {
              return (
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-amber-400 hover:text-amber-300 inline-flex items-center space-x-1"
                >
                  {children}
                  <ExternalLink className="w-3 h-3" />
                </a>
              )
            },
          }}
        >
          {guide}
        </ReactMarkdown>
      </div>
    </div>
  )
}
