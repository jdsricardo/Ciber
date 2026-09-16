<?php

declare(strict_types=1);

namespace App\Presentation;

/** The single HTML shell every page is rendered into. */
final class Layout
{
    public static function render(string $title, string $content): void
    {
        $notice = $_SESSION['notice'] ?? '';
        unset($_SESSION['notice']);
        echo '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . Html::escape($title) . ' · SentinelScope</title>'
            . '<link rel="stylesheet" href="assets/app.css"></head><body>'
            . '<header><a class="brand" href="index.php">Sentinel<span>Scope</span></a>'
            . '<nav><a href="index.php">Painel</a><a href="index.php?page=add">Adicionar aplicação</a>'
            . '<a href="index.php?page=about">Sobre</a></nav>'
            . '</header><main>'
            . ($notice !== '' ? '<div class="notice">' . Html::escape($notice) . '</div>' : '')
            . $content
            . '</main>'
            . '<footer>SentinelScope 1.0 · Avaliação de segurança autorizada, feita para desenvolvedores</footer>'
            . '<script src="assets/app.js" defer></script></body></html>';
    }
}
