import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import jsxA11y from 'eslint-plugin-jsx-a11y'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

export default defineConfig([
  globalIgnores(['dist', 'coverage']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'jsx-a11y': jsxA11y,
    },
    rules: {
      'react-hooks/set-state-in-effect': 'off',
      // Fail the build on a <label> that is not tied to a form control.
      // Only this rule is enabled (rather than jsxA11y.flatConfigs.recommended)
      // to keep the lint gate focused; the full recommended set can be adopted
      // separately once its other findings are triaged.
      //
      // assert: 'either' accepts both valid association forms — explicit
      // (htmlFor/id, used in zones.tsx and record-dialogs.tsx) and nesting
      // (the wrapping <label> in record-form.tsx's FormField).
      // depth: 3 lets the rule see controls wrapped a few elements deep.
      'jsx-a11y/label-has-associated-control': [
        'error',
        { assert: 'either', depth: 3, labelComponents: ['Label'] },
      ],
    },
  },
])
