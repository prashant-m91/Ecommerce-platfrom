/** @type {import('tailwindcss').Config} */
export default {
	content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
	theme: {
		extend: {
			colors: {
				primary: {
					DEFAULT: '#0f766e', // emerald-600 inspired but a bit deeper
					50: '#f0fdfa',
					100: '#ccfbf1',
					200: '#99f6e4',
					300: '#5eead4',
					400: '#2dd4bf',
					500: '#14b8a6',
					600: '#0f766e',
					700: '#0b5e54',
					800: '#07473d',
					900: '#052a25',
				},
				muted: '#94a3b8',
				bg: '#0b1220',
				card: '#0f1724'
			},
			fontFamily: {
				sans: ['Inter', 'ui-sans-serif', 'system-ui'],
			},
			boxShadow: {
				'glass': '0 8px 24px rgba(2,6,23,0.6)',
			},
		},
	},
	plugins: [],
};
