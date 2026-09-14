import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'success'
  size?: 'sm' | 'md' | 'lg'
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-medium transition-all duration-150',
          'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
          'disabled:opacity-50 disabled:pointer-events-none',
          'rounded-md cursor-pointer',
          {
            'bg-accent text-bg hover:bg-accent/90': variant === 'primary',
            'bg-bg-elevated text-text-secondary border border-border hover:bg-bg-hover hover:text-text': variant === 'secondary',
            'text-text-secondary hover:text-text hover:bg-bg-hover': variant === 'ghost',
            'bg-block text-white hover:bg-block/90': variant === 'danger',
            'bg-allow text-bg hover:bg-allow/90': variant === 'success',
          },
          {
            'text-xs h-7 px-2.5': size === 'sm',
            'text-sm h-9 px-4': size === 'md',
            'text-base h-11 px-6': size === 'lg',
          },
          className
        )}
        {...props}
      />
    )
  }
)
Button.displayName = 'Button'
