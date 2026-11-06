<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant;

use Illuminate\Support\ServiceProvider;
use Zubaer\LaravelZubQuant\Console\KeyGenCommand;

class ZubQuantServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/zubquant.php', 'zubquant');

        $this->app->singleton(ZubQuantManager::class, function ($app) {
            $config = $app['config']->get('zubquant', []);
            return new ZubQuantManager(
                $config['public_key'] ?? null,
                $config['private_key'] ?? null,
                $config['verify_key'] ?? null,
                $config['signing_key'] ?? null,
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/zubquant.php' => config_path('zubquant.php'),
            ], 'zubquant-config');

            $this->commands([
                KeyGenCommand::class,
            ]);
        }
    }
}

