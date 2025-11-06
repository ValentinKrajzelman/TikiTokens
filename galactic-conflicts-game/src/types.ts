export interface Position {
  x: number;
  y: number;
}

export interface Size {
  width: number;
  height: number;
}

export interface GameObject extends Position, Size {
  active: boolean;
}

export interface Player extends GameObject {
  speed: number;
}

export interface Alien extends GameObject {
  points: number;
  row: number;
  col: number;
}

export interface Bullet extends GameObject {
  speed: number;
  direction: 'up' | 'down';
}

export interface Shield extends GameObject {
  health: number;
  maxHealth: number;
  damage: boolean[][];
}

export type GameState = 'menu' | 'playing' | 'paused' | 'gameOver' | 'victory';

export interface GameConfig {
  canvasWidth: number;
  canvasHeight: number;
  playerSpeed: number;
  playerSize: { width: number; height: number };
  alienRows: number;
  alienCols: number;
  alienSize: { width: number; height: number };
  alienSpacing: { horizontal: number; vertical: number };
  alienStartY: number;
  alienMoveSpeed: number;
  alienDropDistance: number;
  bulletSpeed: number;
  bulletWidth: number;
  bulletHeight: number;
  shieldCount: number;
  shieldWidth: number;
  shieldHeight: number;
  shieldY: number;
  shieldGridSize: number;
  initialLives: number;
  alienShootProbability: number;
}
