<?php
namespace Wangyongdong\LaravelCas\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Application;

class CASAuth
{

    /**
     * @var Guard
     */
    protected $auth;

    /**
     * @var Application|mixed
     */
    protected $cas;

    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
        $this->cas = app('cas');
    }

    /**
     * Handle an incoming request.
     *
     * @param $request
     * @param Closure $next
     * @return \Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\Response|mixed|\Symfony\Component\HttpFoundation\Response|void
     */
    public function handle($request, Closure $next)
    {
        if($this->cas->checkAuthentication())
        {
            $request->offsetSet('userid', $this->cas->user());
            // Store the user credentials in a Laravel managed session
            session(['userid' => $this->cas->user()]);
            session()->put('userid', $this->cas->user());
        } else {
            if ($request->ajax() || $request->wantsJson()) {
                return response('Unauthorized.', 401);
            }
            $this->cas->forceAuthentication();
        }

        return $next($request);
    }
}
