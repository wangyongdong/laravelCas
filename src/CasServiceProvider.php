<?php
namespace Wangyongdong\LaravelCas;

use Illuminate\Support\ServiceProvider;

class CasServiceProvider extends ServiceProvider
{

    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/config/cas.php' => config_path('cas.php'),
            ], 'cas');
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/config/cas.php', 'cas');
        $this->app->singleton('cas', function ($app) {
            $config = $this->app['config']->get('cas');
            return new CasManager($config);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['cas'];
    }

}
