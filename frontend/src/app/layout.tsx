import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'AMG DataOps Cloud',
  description: 'Enterprise Data Processing & Threat Intelligence Engine',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#080C14] text-white antialiased">{children}</body>
    </html>
  )
}
