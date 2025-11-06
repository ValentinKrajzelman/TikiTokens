# Galactic Conflicts

A fully polished Space Invaders clone built with React, TypeScript, and Canvas API.

## Features

- Classic Space Invaders gameplay with modern polish
- Programmatically generated graphics (no image assets)
- Smooth 60fps animations with requestAnimationFrame
- Complete game states: Menu, Playing, Game Over, and Victory
- Progressive difficulty - aliens speed up as their numbers decrease
- Destructible shield barriers
- Score tracking with high score persistence
- Lives system (3 lives)
- Responsive keyboard controls
- Retro-futuristic UI design

## Controls

- **Arrow Keys (← →)**: Move player ship left and right
- **Spacebar**: Shoot bullets (max 3 on screen)

## Gameplay

Defend Earth from waves of alien invaders! Destroy all aliens before they reach the bottom of the screen or eliminate you. Use the shields for protection, but they won't last forever.

### Scoring

- Row 1 (Top): 50 points per alien
- Row 2: 40 points per alien
- Row 3: 30 points per alien
- Row 4: 20 points per alien
- Row 5 (Bottom): 10 points per alien

### Win Conditions

- **Victory**: Destroy all aliens
- **Game Over**: Lose all 3 lives or aliens reach the bottom

## Technology Stack

- **React 19** - UI framework
- **TypeScript** - Type safety and better developer experience
- **Canvas API** - High-performance 2D rendering
- **Vite** - Lightning-fast build tool
- **CSS3** - Animations and retro-futuristic styling

## Project Structure

```
src/
├── App.tsx       # Main application component
├── Game.tsx      # Game logic, rendering, and state management
├── types.ts      # TypeScript type definitions
├── index.css     # Global styles and animations
└── main.tsx      # React entry point
```

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Game Architecture

The game uses a clean separation of concerns:

- **Game Loop**: Uses `requestAnimationFrame` for smooth 60fps rendering
- **State Management**: React hooks with ref-based game state for optimal performance
- **Collision Detection**: Efficient AABB (Axis-Aligned Bounding Box) collision detection
- **Rendering**: Canvas 2D context for performant graphics
- **Input Handling**: Keyboard event listeners with state tracking

## Performance

- Targets 60fps with requestAnimationFrame
- Efficient collision detection algorithms
- Optimized re-renders with proper React patterns
- No external image assets - all graphics programmatically generated

## Future Enhancements

Potential improvements for future versions:

- Sound effects and background music
- Power-ups (rapid fire, shield repair, extra life)
- Multiple difficulty levels
- Additional alien types with unique behaviors
- Boss battles
- Particle effects for explosions
- Leaderboard with localStorage persistence
- Mobile touch controls
- Multiple levels with increasing difficulty

## License

MIT

## Credits

Built as a demonstration of modern web game development with React and TypeScript.
