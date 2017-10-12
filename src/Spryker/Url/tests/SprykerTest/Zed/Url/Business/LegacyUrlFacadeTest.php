<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Url\Business;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\RedirectTransfer;
use Generated\Shared\Transfer\UrlTransfer;
use Spryker\Zed\Locale\Business\LocaleFacade;
use Spryker\Zed\Touch\Persistence\TouchQueryContainer;
use Spryker\Zed\Url\Business\UrlFacade;
use Spryker\Zed\Url\Persistence\UrlQueryContainer;
use Symfony\Component\HttpFoundation\Response;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Url
 * @group Business
 * @group Facade
 * @group LegacyUrlFacadeTest
 * Add your own group annotations below this line
 */
class LegacyUrlFacadeTest extends Unit
{
    /**
     * @var \Spryker\Zed\Url\Business\UrlFacade
     */
    protected $urlFacade;

    /**
     * @var \Spryker\Zed\Url\Persistence\UrlQueryContainerInterface
     */
    protected $urlQueryContainer;

    /**
     * @var \Spryker\Zed\Touch\Persistence\TouchQueryContainer
     */
    protected $touchQueryContainer;

    /**
     * @var \Spryker\Zed\Locale\Business\LocaleFacade
     */
    protected $localeFacade;

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->urlFacade = new UrlFacade();
        $this->localeFacade = new LocaleFacade();
        $this->urlQueryContainer = new UrlQueryContainer();
        $this->touchQueryContainer = new TouchQueryContainer();
    }

    /**
     * @return void
     */
    public function testCreateUrlInsertsAndReturnsSomething()
    {
        $urlQuery = $this->urlQueryContainer->queryUrls();
        $locale = $this->localeFacade->createLocale('CBCDE');
        $redirect = $this->urlFacade->createRedirect('/some/url/like/string2');

        $urlCountBeforeCreation = $urlQuery->count();
        $newUrl = $this->urlFacade->createUrl('/some/url/like/string', $locale, 'redirect', $redirect->getIdUrlRedirect());
        $urlCountAfterCreation = $urlQuery->count();

        $this->assertTrue($urlCountAfterCreation > $urlCountBeforeCreation);

        $this->assertNotNull($newUrl->getIdUrl());
    }

    /**
     * @return void
     */
    public function testSaveUrlInsertsAndReturnsSomethingOnCreate()
    {
        $urlQuery = $this->urlQueryContainer->queryUrls();
        $redirect = $this->urlFacade->createRedirect('/YetSomeOtherPageUrl2');

        $url = new UrlTransfer();
        $url
            ->setUrl('/YetSomeOtherPageUrl')
            ->setFkLocale($this->localeFacade->createLocale('QWERT')->getIdLocale())
            ->setResourceType('redirect')
            ->setResourceId($redirect->getIdUrlRedirect());

        $urlCountBeforeCreation = $urlQuery->count();
        $url = $this->urlFacade->saveUrl($url);
        $urlCountAfterCreation = $urlQuery->count();

        $this->assertTrue($urlCountAfterCreation > $urlCountBeforeCreation);

        $this->assertNotNull($url->getIdUrl());
    }

    /**
     * @return void
     */
    public function testSaveUrlUpdatesSomething()
    {
        $url = new UrlTransfer();
        $urlQuery = $this->urlQueryContainer->queryUrl('/SoManyPageUrls');
        $redirect1 = $this->urlFacade->createRedirect('/SoManyPageUrls2');
        $redirect2 = $this->urlFacade->createRedirect('/SoManyPageUrls3');

        $url
            ->setUrl('/SoManyPageUrls')
            ->setFkLocale($this->localeFacade->createLocale('WERTZ')->getIdLocale())
            ->setResourceType('redirect')
            ->setResourceId($redirect1->getIdUrlRedirect());

        $url = $this->urlFacade->saveUrl($url);

        $this->assertEquals($redirect1->getIdUrlRedirect(), $urlQuery->findOne()->getResourceId());

        $url->setResourceId($redirect2->getIdUrlRedirect());
        $this->urlFacade->saveUrl($url);

        $this->assertEquals($redirect2->getIdUrlRedirect(), $urlQuery->findOne()->getResourceId());
    }

    /**
     * @return void
     */
    public function testHasUrlId()
    {
        $locale = $this->localeFacade->createLocale('UNIXA');
        $redirect = $this->urlFacade->createRedirect('/SoManyPageUrls4');

        $idPageUrl = $this->urlFacade->createUrl('/abcdefg', $locale, 'redirect', $redirect->getIdUrlRedirect())->getIdUrl();

        $this->assertTrue($this->urlFacade->hasUrlId($idPageUrl));
    }

    /**
     * @return void
     */
    public function testGetUrlByPath()
    {
        $locale = $this->localeFacade->createLocale('DFGHE');
        $redirect = $this->urlFacade->createRedirect('/SoManyPageUrls5');

        $this->urlFacade->createUrl('/someOtherPageUrl', $locale, 'redirect', $redirect->getIdUrlRedirect());

        $url = $this->urlFacade->getUrlByPath('/someOtherPageUrl');
        $this->assertNotNull($url);

        $this->assertEquals('/someOtherPageUrl', $url->getUrl());
        $this->assertEquals($locale->getIdLocale(), $url->getFkLocale());
    }

    /**
     * @return void
     */
    public function testGetUrlById()
    {
        $locale = $this->localeFacade->createLocale('DFGHX');
        $redirect = $this->urlFacade->createRedirect('/SoManyPageUrls5');

        $id = $this->urlFacade->createUrl('/someOtherPageUrl2', $locale, 'redirect', $redirect->getIdUrlRedirect())->getIdUrl();

        $url = $this->urlFacade->getUrlById($id);
        $this->assertNotNull($url);

        $this->assertEquals('/someOtherPageUrl2', $url->getUrl());
        $this->assertEquals($locale->getIdLocale(), $url->getFkLocale());
    }

    /**
     * @return void
     */
    public function testTouchUrlActive()
    {
        $locale = $this->localeFacade->createLocale('ABCDE');
        $redirect = $this->urlFacade->createRedirect('/ARedirectUrl');

        $idUrl = $this->urlFacade->createUrl('/aPageUrl', $locale, 'redirect', $redirect->getIdUrlRedirect())->getIdUrl();

        $touchQuery = $this->touchQueryContainer->queryTouchEntry('url', $idUrl);
        $touchQuery->setQueryKey('count');
        $this->assertEquals(0, $touchQuery->count());

        $touchQuery->setQueryKey(TouchQueryContainer::TOUCH_ENTRY_QUERY_KEY);
        $this->urlFacade->touchUrlActive($idUrl);

        $touchQuery->setQueryKey('count');
        $this->assertEquals(1, $touchQuery->count());
    }

    /**
     * @return void
     */
    public function testCreateRedirectInsertsAndReturnsSomething()
    {
        $redirectQuery = $this->urlQueryContainer->queryRedirects();

        $redirectCountBeforeCreation = $redirectQuery->count();
        $newRedirect = $this->urlFacade->createRedirect('/this/other/url');
        $redirectCountAfterCreation = $redirectQuery->count();

        $this->assertTrue($redirectCountAfterCreation > $redirectCountBeforeCreation);

        $this->assertNotNull($newRedirect->getIdUrlRedirect());
    }

    /**
     * @return void
     */
    public function testSaveRedirectInsertsAndReturnsSomethingOnCreate()
    {
        $redirect = new RedirectTransfer();
        $redirect->setToUrl('/pageToUrl');
        $redirect->setStatus(Response::HTTP_MOVED_PERMANENTLY);

        $redirectQuery = $this->urlQueryContainer->queryRedirects();

        $redirectCountBeforeCreation = $redirectQuery->count();
        $redirect = $this->urlFacade->saveRedirect($redirect);
        $redirectCountAfterCreation = $redirectQuery->count();

        $this->assertTrue($redirectCountAfterCreation > $redirectCountBeforeCreation);

        $this->assertNotNull($redirect->getIdUrlRedirect());
    }

    /**
     * @return void
     */
    public function testSaveRedirectUpdatesSomething()
    {
        $redirect = new RedirectTransfer();
        $redirect->setToUrl('/pageToUrl2');
        $redirect->setStatus(Response::HTTP_MOVED_PERMANENTLY);

        $redirect = $this->urlFacade->saveRedirect($redirect);

        $redirectQuery = $this->urlQueryContainer->queryRedirectById($redirect->getIdUrlRedirect());

        $this->assertEquals('/pageToUrl2', $redirectQuery->findOne()->getToUrl());

        $redirect->setToUrl('/redirectingToUrl');
        $this->urlFacade->saveRedirect($redirect);

        $this->assertEquals('/redirectingToUrl', $redirectQuery->findOne()->getToUrl());
    }
}
