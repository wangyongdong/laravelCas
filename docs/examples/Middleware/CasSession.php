<?php

namespace Wangyongdong\LaravelCas\Middleware;

use Closure;
use Illuminate\Http\Request;

class CasSession
{
    protected $sess_user = 'userid';

    public function __construct()
    {
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (app('cas')->checkAuthentication()) {
            $request->session()->put($this->sess_user, app('cas')->user());
        } else {
            $request->session()->forget($this->sess_user);
        }

        return $next($request);
    }
}
