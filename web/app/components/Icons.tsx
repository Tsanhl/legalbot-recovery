import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function IconBase({ size = 20, children, ...props }: IconProps) {
  return (
    <svg
      aria-hidden="true"
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      {...props}
    >
      {children}
    </svg>
  );
}

const stroke = {
  stroke: "currentColor",
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  strokeWidth: 1.8,
};

export const Icons = {
  mark: (props: IconProps) => (
    <IconBase {...props}>
      <path {...stroke} d="M4 19h16M7 17l5-12 5 12M8.5 13.5h7" />
    </IconBase>
  ),
  plus: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M12 5v14M5 12h14" /></IconBase>
  ),
  chat: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M20 15a3 3 0 0 1-3 3H9l-5 3v-6a3 3 0 0 1-1-2V7a3 3 0 0 1 3-3h11a3 3 0 0 1 3 3z" /></IconBase>
  ),
  dashboard: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M4 4h6v7H4zM14 4h6v4h-6zM14 12h6v8h-6zM4 15h6v5H4z" /></IconBase>
  ),
  activity: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M3 12h4l2.2-6 4.1 12 2.2-6H21" /></IconBase>
  ),
  globe: (props: IconProps) => (
    <IconBase {...props}><circle {...stroke} cx="12" cy="12" r="9" /><path {...stroke} d="M3 12h18M12 3c3.5 3.8 3.5 14.2 0 18M12 3c-3.5 3.8-3.5 14.2 0 18" /></IconBase>
  ),
  target: (props: IconProps) => (
    <IconBase {...props}><circle {...stroke} cx="12" cy="12" r="8" /><circle {...stroke} cx="12" cy="12" r="3" /></IconBase>
  ),
  paperclip: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="m20 11-8.3 8.3a5 5 0 0 1-7-7l9-9a3.5 3.5 0 0 1 5 5l-9 9a2 2 0 1 1-2.8-2.8l8-8" /></IconBase>
  ),
  send: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="m21 3-7.5 18-3.3-7.2L3 10.5zM10.2 13.8 21 3" /></IconBase>
  ),
  shield: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M12 3 5 6v5c0 4.7 2.9 8.2 7 10 4.1-1.8 7-5.3 7-10V6z" /><path {...stroke} d="m9 12 2 2 4-5" /></IconBase>
  ),
  book: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M4 5.5A2.5 2.5 0 0 1 6.5 3H11v16H6.5A2.5 2.5 0 0 0 4 21zM20 5.5A2.5 2.5 0 0 0 17.5 3H13v16h4.5A2.5 2.5 0 0 1 20 21z" /></IconBase>
  ),
  external: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M14 4h6v6M20 4l-9 9M18 13v6H5V6h6" /></IconBase>
  ),
  close: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="m6 6 12 12M18 6 6 18" /></IconBase>
  ),
  check: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="m5 12 4 4L19 6" /></IconBase>
  ),
  alert: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M12 3 2.8 20h18.4zM12 9v4M12 17h.01" /></IconBase>
  ),
  menu: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M4 7h16M4 12h16M4 17h16" /></IconBase>
  ),
  copy: (props: IconProps) => (
    <IconBase {...props}><rect {...stroke} x="8" y="8" width="11" height="11" rx="2" /><path {...stroke} d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" /></IconBase>
  ),
  file: (props: IconProps) => (
    <IconBase {...props}><path {...stroke} d="M6 3h8l4 4v14H6zM14 3v5h5" /></IconBase>
  ),
  search: (props: IconProps) => (
    <IconBase {...props}><circle {...stroke} cx="11" cy="11" r="7" /><path {...stroke} d="m20 20-4-4" /></IconBase>
  ),
};
