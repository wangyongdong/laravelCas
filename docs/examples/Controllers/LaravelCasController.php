<?php
namespace Wangyongdong\LaravelCas\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class LaravelCasController extends Controller
{

    /**
     * User logout.
     */
    public function logout(Request $request)
    {
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return app('cas')->logout();
    }
}
