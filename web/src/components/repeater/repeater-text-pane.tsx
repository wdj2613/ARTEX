"use client";

import * as React from "react";

import { CopyButton } from "@/components/copy-button";
import { Textarea } from "@/components/ui/textarea";

export function RepeaterTextPane({
  id,
  label,
  value,
  onChange,
  disabled,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange?: (value: string) => void;
  disabled?: boolean;
  placeholder?: string;
}) {
  const gutter = React.useRef<HTMLPreElement>(null);
  const lines = React.useMemo(() => value.split(/\r\n|\r|\n/).length, [value]);
  const numbers = React.useMemo(() => Array.from({ length: lines }, (_, index) => index + 1).join("\n"), [lines]);
  return (
    <div className="flex min-h-[280px] min-w-0 flex-1 flex-col gap-2 xl:min-h-0">
      <div className="flex items-center gap-2">
        <label htmlFor={id} className="font-medium text-xs">
          {label}
        </label>
        <span className="text-muted-foreground text-xs tabular-nums">{lines} 行</span>
        <CopyButton text={value} label={`复制${label}`} className="ml-auto" />
      </div>
      <div className="flex min-h-0 flex-1 overflow-hidden rounded-lg border border-input focus-within:border-ring">
        <div
          aria-hidden="true"
          className="w-12 shrink-0 overflow-hidden border-r bg-muted/30 text-right text-muted-foreground"
        >
          <pre ref={gutter} className="select-none px-2 py-2 font-mono text-xs leading-5">
            {numbers}
          </pre>
        </div>
        <Textarea
          id={id}
          value={value}
          onChange={(event) => onChange?.(event.target.value)}
          onScroll={(event) => {
            if (gutter.current) gutter.current.style.transform = `translateY(-${event.currentTarget.scrollTop}px)`;
          }}
          disabled={disabled}
          readOnly={!onChange}
          placeholder={placeholder}
          wrap="off"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          className="field-sizing-fixed h-full max-h-none min-h-0 w-0 flex-1 resize-none rounded-none border-0 px-3 py-2 font-mono text-xs leading-5 focus-visible:ring-0 md:text-xs"
        />
      </div>
    </div>
  );
}
